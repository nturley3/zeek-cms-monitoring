# Purpose

Detects authentication attempts to Drupal, Wordpress, and Joomla content management systems (CMS) and generates a new log type.

# Installation/Upgrade

This script was tested using Zeek 3.0.11

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-cms-monitoring

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-cms-monitoring

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

# Configuration

No additional Zeek configuration is necessary for this package.

# Tested CMS Versions
| CMS | Versions |
| Drupal | 8.9 |
| Joomla |  |
| Wordpress | 4.9, 5.8 |

# Generated Outputs

This package creates a new log type called cms. 
| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| (Connection Info) | Various | The typical id.orig_h, id.resp_h, etc. |
| cms_uri | `string` | The login URL. |
| cms_timeout | `bool` | Zeek was unable to track the entire login session. |
| lv_dist | `count` | The [Levenshtein Distance](https://en.wikipedia.org/wiki/Levenshtein_distance) between the username and the password. |
| password | `count` | Identifies the password submitted. |
| pw_length | `count` | Identifies the number of characters in a password. |
| username | `string` | The username submitted. |
| user_agent | `string` | The user-agent of the HTTP request. |

# Usage

Due to CMS popularity especially among those without strong IT or security backgrounds, threat actors target CMS websites.
Often the websites have default configurations that do not provide adequate protections against
credential stuffing or brute force attacks. Attackers might also find credentials exposed in other ways.

A security analyst can examine the cms log to determine if a successful login to a CMS website is suspicious. An example of a suspicious login is a series of unsuccessful login attempts of various password lengths and Levenshtein Distances followed by a successful login attempt which indicates a successful brute force attack. Another suspicious login could be from an IP address outside what is typically expected, such as from a foreign country. 

A security analysts could also identify weak credentials used by legitimate personnel. A low Levenshtein Distance or password length indicates the credentials are more susceptible to a brute force attack.

Type: Threat Hunting
