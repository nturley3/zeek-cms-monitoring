##! Module for handling CMS Drupal data

module CMS;

function drupal_check_login_complete(c: connection, user_id: string)
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
        log$username = cms_users[user_id]["drupal"]$username;
        log$pw_length = |cms_users[user_id]["drupal"]$password|;
        log$cms_uri = cms_users[user_id]["drupal"]?$cms_uri ? cms_users[user_id]["drupal"]$cms_uri : "unknown";
        log$cms_app = "drupal";
        log$lv_dist = cms_users[user_id]["drupal"]$lv_dist;

        # Set the detected user agent string
        if(cms_users[user_id]["drupal"]?$user_agent) {
            log$user_agent = cms_users[user_id]["drupal"]$user_agent;
        }

        # Only expose passwords on specific ports
        if(c$id$resp_p in cleartext_checked_ports) {
            log$password = cms_users[user_id]["drupal"]$password;
        }
        else
        {
            log$password = "<redacted>";
        }

        # Check login and cookie status
        if("drupal" in cms_users[user_id] && /SESS.*=.*/ in join_string_set(cms_users[user_id]["drupal"]$set_cookie, "-")) {
            # Drupal authentication was successful
            log$cms_success = T;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        } 
        else if("drupal" in cms_users[user_id] && /SESS.*=.*/ !in join_string_set(cms_users[user_id]["drupal"]$set_cookie, "-")) {
            # Drupal login failure
            log$cms_success = F;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        }
        else {
            # We're not sure what happened. Return and let document expire. 
            # TODO: Refactor. This may not be needed. 
            return;
        }
    }
}

# Drupal
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    if(!c$http?$uri)
        return;

    local lp_attrs: table[string] of string;
    local session: SessionContext;
    local user_id: string;
    local cms_uri: set[string];
    local cookies: table[string] of string;

    if(c$http?$post_body) {
        if(/name=/ !in c$http$post_body && /pass=/ !in c$http$post_body) {
            return;
        }

        lp_attrs = CMS::parse_post_body(c$http$post_body);
        # If the following form attributes are seen, relatively certain we are seeing Drupal
        # Drupal 7 uses form_id = user_login_block
        # Drupal 8 used form_id = user_login_form
        if("name" in lp_attrs && "pass" in lp_attrs && "op" in lp_attrs && "form_id" in lp_attrs && /user_login_.*/ in lp_attrs["form_id"]) {
            # Drupal detection
            # print(lp_attrs);
            user_id = lp_attrs["name"];

            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["name"];
            # TODO: Refactor below when password field is not seen in POST payload
            #if("pass" !in lp_attrs)
            #{
            #    # Return since login checks won't work if password is missing
            #    Reporter::warning(fmt("User ID %s was missing password in headers. Incomplete CMS Drupal login.", session$username));
            #    return;
            #}
            session$password = lp_attrs["pass"];
            session$lv_dist = levenshtein_distance(lp_attrs["name"], lp_attrs["pass"]);

            session$set_cookie = get_set_cookie(hlist);
            cookies = get_cookie_values(session$set_cookie);
            session$cms_uri = HTTP::build_url(c$http);

            if(c$http?$user_agent)
            {
                # Set user agent if available
                session$user_agent = c$http$user_agent;
            }
            cms_users[user_id] = table(
                ["drupal"] = session
            );
            drupal_check_login_complete(c, user_id);

            # Redact sensitive information
            c$http$post_body = "<redacted>";
        }
    }
}
