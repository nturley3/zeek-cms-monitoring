##! Module for handling CMS data

@load base/protocols/http
@load base/utils/urls
@load base/protocols/http/utils
@load base/frameworks/notice

module CMS;

export {
    ## CAS event log ID definition.
    redef enum Log::ID += { LOG };

    type Info: record {
        ## CAS event timestamp
        ts:   time    &log;
        ## Unique ID for the connection.
        uid:  string  &log;
        ## Connection details.
        id:   conn_id &log;
        ## CAS username detected
        username:  string  &log &optional;
        ## CAS password detected
        password: string  &log &optional;
        ## CMS service
        cms_uri: string &log &optional;
        ## CMS application
        cms_app: string &log &optional;
        ## CMS login success
        cms_success: bool &log &optional;
        ## CMS timeout
        cms_timeout: bool &log &optional;
        ## Levenshtein Distance
        lv_dist: count &log &optional;
        ## Password length
        pw_length: count &log &optional;
        ## User agent
        user_agent: string &log &optional;
    };

    ## Time after which a seen cookie is forgotten.
    const session_expiration = 90sec &redef;
    
    ## Ports where passwords will be exposed
    const cleartext_checked_ports: set[port] = { 80/tcp, 8080/tcp  } &redef;
}

## Per user session state
type SessionContext: record
{
    user_agent: string &optional;  
    conn: string &optional;       
    id: conn_id &optional;
    cookie: set[string] &optional;    
    set_cookie: set[string] &optional;
    cms_uri: string &optional; 
    cms_app: string &optional; 
    cms_success: bool &log &optional;
    cms_timeout: bool &log &optional;
    username: string &optional;
    password: string &optional;
    lv_dist: count &optional;
};

## This function expires documents in the user state tracking table when session_expiration has been reached.
## This is important for controlling memory consumption and making sure documents are cleaned out if Zeek
## was unable to track the entire session
function expire_doc(t: table[string] of table[string] of SessionContext, idx: string): interval
{
    local cms_app: string;
    if("drupal" in t[idx]) {
        cms_app = "drupal";
    } 
    else if("wordpress" in t[idx]) {
        cms_app = "wordpress";
    } 
    else if("joomla" in t[idx]) {
        cms_app = "joomla";
    }
    else {
        cms_app = "unknown";
    }

    if(cms_app != "unknown") {
        # Build the record and write the log
        local log: Info = [
            $ts = network_time(),
            $uid = t[idx][cms_app]$conn,
            $id = t[idx][cms_app]$id
        ];
        log$username = t[idx][cms_app]$username;
        log$cms_uri = t[idx][cms_app]$cms_uri;
        log$pw_length = |t[idx][cms_app]$password|;
        # log$cms_success = T;
        log$cms_timeout = T;
        # log$duo_success = F; # Don't set since we don't know if the Duo challenge was successful or not
        log$lv_dist = t[idx][cms_app]$lv_dist;
        if(t[idx][cms_app]?$user_agent) {
            log$user_agent = t[idx][cms_app]$user_agent;
        }
        Log::write(CMS::LOG, log);
        Reporter::info(fmt("CMS EXPIRE: %s", t[idx]));
    }

    return 0 secs;
}

## User state tracking table
global cms_users: table[string] of table[string] of SessionContext &read_expire = session_expiration &expire_func = expire_doc;

function parse_post_body(post_body: string) : table[string] of string
{
    local params: string_vec;
    local attrs: table[string] of string;

    # First, split the POST parameters
    params = split_string(post_body, /\&/);

    # Second, build table of key/value pairs
    for(idx in params)
    {
        # Split the key/value pairs
        local tmp: string_vec = split_string(params[idx], /=/);
        attrs[tmp[0]] = 1 in tmp ? unescape_URI(tmp[1]) : "";
    }

    return attrs;
}

function get_cookie_values(s: set[string]): table[string] of string
{
    for(element in s)
    {
        local elements: string_vec;
        local attrs: string_vec;
        local key_values: table[string] of string;
        elements = split_string(element, /;/);
        for(idx in elements)
        {
            # print(strip(elements[idx]));
            attrs = split_string(strip(elements[idx]), /=/);
            #print(attrs);
            key_values[attrs[0]] = 1 in attrs ? attrs[1] : "";
        }
    }
    return key_values;
}

function get_set_cookie(hlist: mime_header_list): set[string]
{
    local cookies: set[string] = set();
    for ( h in hlist  )
    {
        if ( hlist[h]$name == "SET-COOKIE" )
        {
            add cookies[hlist[h]$value];
        }
    }
    return cookies;
}

event bro_init()
{
    # Create the new CMS event logging stream (cms.log)
    local stream = [$columns=Info, $path="cms"];
    Log::create_stream(CMS::LOG, stream);
}

