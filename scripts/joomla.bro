##! Module for handling CMS Joomla data

module CMS;

function joomla_check_login_complete(c: connection, user_id: string)
{
    # Build the record and write the log
    local log: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id
    ];

    if(user_id != "")
    {
        # Set common fields
        log$username = cms_users[user_id]["joomla"]$username;
        log$pw_length = |cms_users[user_id]["joomla"]$password|;
        log$cms_uri = cms_users[user_id]["joomla"]?$cms_uri ? cms_users[user_id]["joomla"]$cms_uri : "unknown";
        log$cms_app = "joomla";
        log$lv_dist = cms_users[user_id]["joomla"]$lv_dist;

        # Set the detected user agent string
        if(cms_users[user_id]["joomla"]?$user_agent) {
            log$user_agent = cms_users[user_id]["joomla"]$user_agent;
        }

        # Only expose passwords on specific ports
        if(c$id$resp_p in cleartext_checked_ports) {
            log$password = cms_users[user_id]["joomla"]$password;
        }
        else
        {
            log$password = "<redacted>";
        }

        # Check login and cookie status
        if("joomla" in cms_users[user_id] && /joomla_user_state=logged_in.*/ in join_string_set(cms_users[user_id]["joomla"]$set_cookie, "-")) {
            # Joomla authentication was successful
            log$cms_success = T;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        } 
        else if("joomla" in cms_users[user_id] && /joomla_user_state=logged_in.*/ !in join_string_set(cms_users[user_id]["joomla"]$set_cookie, "-")) {
            # Joomla login failure
            log$cms_success = F;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        }
        else {
            #TODO: Refactor. This may not be needed. 
            # We're not sure what happened. Return and let document expire. 
            return;
        }
    }
}

# Joomla
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    if(!c$http?$uri)
        return;

    local lp_attrs: table[string] of string;
    local session: SessionContext;
    local user_id: string;
    local cms_uri: set[string];
    local cookies: table[string] of string;

    if(c$http?$post_body) {
        if(/username=/ !in c$http$post_body && /password=/ !in c$http$post_body) {
            return;
        }

        lp_attrs = CMS::parse_post_body(c$http$post_body);
        # For Joomla, different values provided based on where the user is logging in from
        # Username/password always provided
        # task = user.login appears when user is not logging in from primary form
        # Otherwise we see the "return" field with a base64 encoded value of where to return (url) the user after login        
        if("username" in lp_attrs && "password" in lp_attrs && 
            ( ("task" in lp_attrs && /user\.login/ in lp_attrs["task"]) || ("return" in lp_attrs) ) ) {
            # Drupal detection
            # print(lp_attrs);
            user_id = lp_attrs["username"];

            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["username"];
            #if("password" !in lp_attrs)
            #{
            #    # Return since login checks won't work if password is missing
            #    Reporter::warning(fmt("User ID %s was missing password in headers. Incomplete CMS Joomla login.", session$username));
            #    return;
            #}
            session$password = lp_attrs["password"];
            session$lv_dist = levenshtein_distance(lp_attrs["username"], lp_attrs["password"]);

            session$set_cookie = get_set_cookie(hlist);
            cookies = get_cookie_values(session$set_cookie);
            session$cms_uri = HTTP::build_url(c$http);

            if(c$http?$user_agent)
            {
                # Set user agent if available
                session$user_agent = c$http$user_agent;
            }
            cms_users[user_id] = table(
                ["joomla"] = session
            );
            joomla_check_login_complete(c, user_id);

            # Redact sensitive information
            c$http$post_body = "<redacted>";
        }
    }
}
