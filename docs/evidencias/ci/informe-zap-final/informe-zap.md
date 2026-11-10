# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Informational | 7 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Info | Informational | https://localhost:8443 | Percentage of responses with status code 2xx | 50 % |
| Info | Informational | https://localhost:8443 | Percentage of responses with status code 3xx | 8 % |
| Info | Informational | https://localhost:8443 | Percentage of responses with status code 4xx | 41 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with content type application/javascript | 4 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with content type application/json | 45 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with content type text/css | 4 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with content type text/html | 45 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with method GET | 63 % |
| Info | Informational | https://localhost:8443 | Percentage of endpoints with method POST | 36 % |
| Info | Informational | https://localhost:8443 | Count of total endpoints | 22    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Absence of Anti-CSRF Tokens | Medium | Systemic |
| Authentication Request Identified | Informational | 8 |
| Information Disclosure - Suspicious Comments | Informational | 1 |
| Modern Web Application | Informational | Systemic |
| Non-Storable Content | Informational | Systemic |
| Re-examine Cache-control Directives | Informational | Systemic |
| Storable but Non-Cacheable Content | Informational | 5 |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 12 |




## Alert Detail



### [ Absence of Anti-CSRF Tokens ](https://www.zaproxy.org/docs/alerts/10202/)



##### Medium (Low)

### Description

No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: https://localhost:8443/
  * Node Name: `https://localhost:8443/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form id="login-form" method="post" autocomplete="on">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "login-otp" "login-password" "login-username" ].`
* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form id="login-form" method="post" autocomplete="on">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "login-otp" "login-password" "login-username" ].`
* URL: https://localhost:8443/app/%3Fnote
  * Node Name: `https://localhost:8443/app/ (note)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form id="login-form" method="post" autocomplete="on">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "login-otp" "login-password" "login-username" ].`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form id="login-form" method="post" autocomplete="on">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "login-otp" "login-password" "login-username" ].`
* URL: https://localhost:8443/app/%3Ftype=firewall
  * Node Name: `https://localhost:8443/app/ (type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form id="login-form" method="post" autocomplete="on">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "login-otp" "login-password" "login-username" ].`

Instances: Systemic


### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (Low)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/ ()(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/`
* URL: https://localhost:8443/app/%3Fnote
  * Node Name: `https://localhost:8443/app/ (note)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?note`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (note,severity,status)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?note&severity=critical&status=new`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,severity,status,type)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?note&severity=critical&status=new&type=firewall`
* URL: https://localhost:8443/app/%3Fnote&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,type)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?note&type=firewall`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?severity=critical&status=new`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (severity,status,type)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?severity=critical&status=new&type=firewall`
* URL: https://localhost:8443/app/%3Ftype=firewall
  * Node Name: `https://localhost:8443/app/ (type)(otp,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=https://localhost:8443/app/?type=firewall`


Instances: 8

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Medium)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: https://localhost:8443/app/app.js
  * Node Name: `https://localhost:8443/app/app.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ertas e inventario. Todo el contenido que vi`
  * Other Info: `The following pattern was used: \bTODO\b and was detected in likely comment: "// Consola del analista: vistas de login, alertas e inventario. Todo el contenido que viene de la API", see evidence field for the suspicious comment/snippet.`


Instances: 1

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: https://localhost:8443/
  * Node Name: `https://localhost:8443/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module" src="app.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module" src="app.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: https://localhost:8443/app/%3Fnote
  * Node Name: `https://localhost:8443/app/ (note)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module" src="app.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module" src="app.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: https://localhost:8443/app/%3Ftype=firewall
  * Node Name: `https://localhost:8443/app/ (type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module" src="app.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`

Instances: Systemic


### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: https://localhost:8443/
  * Node Name: `https://localhost:8443/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost:8443/app
  * Node Name: `https://localhost:8443/app`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost:8443/robots.txt
  * Node Name: `https://localhost:8443/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost:8443/sitemap.xml
  * Node Name: `https://localhost:8443/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/ ()(otp,password,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Re-examine Cache-control Directives ](https://www.zaproxy.org/docs/alerts/10015/)



##### Informational (Low)

### Description

The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.

* URL: https://localhost:8443/
  * Node Name: `https://localhost:8443/`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/%3Fnote
  * Node Name: `https://localhost:8443/app/ (note)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/%3Ftype=firewall
  * Node Name: `https://localhost:8443/app/ (type)`
  * Method: `GET`
  * Parameter: `cache-control`
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``

Instances: Systemic


### Solution

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching ](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching)
* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
* [ https://grayduck.mn/2021/09/13/cache-control-recommendations/ ](https://grayduck.mn/2021/09/13/cache-control-recommendations/)


#### CWE Id: [ 525 ](https://cwe.mitre.org/data/definitions/525.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: https://localhost:8443/
  * Node Name: `https://localhost:8443/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/
  * Node Name: `https://localhost:8443/app/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/%3Fnote
  * Node Name: `https://localhost:8443/app/ (note)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/app.css
  * Node Name: `https://localhost:8443/app/app.css`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: https://localhost:8443/app/app.js
  * Node Name: `https://localhost:8443/app/app.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``


Instances: 5

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (note,severity,status)`
  * Method: `GET`
  * Parameter: `severity`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&severity=critical&status=new

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
severity=critical

The user-controlled value was:
critical`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (note,severity,status)`
  * Method: `GET`
  * Parameter: `status`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&severity=critical&status=new

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
status=new

The user-controlled value was:
new`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,severity,status,type)`
  * Method: `GET`
  * Parameter: `severity`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
severity=critical

The user-controlled value was:
critical`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,severity,status,type)`
  * Method: `GET`
  * Parameter: `status`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
status=new

The user-controlled value was:
new`
* URL: https://localhost:8443/app/%3Fnote&severity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,severity,status,type)`
  * Method: `GET`
  * Parameter: `type`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
type=firewall

The user-controlled value was:
firewall`
* URL: https://localhost:8443/app/%3Fnote&type=firewall
  * Node Name: `https://localhost:8443/app/ (note,type)`
  * Method: `GET`
  * Parameter: `type`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?note&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
type=firewall

The user-controlled value was:
firewall`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)`
  * Method: `GET`
  * Parameter: `severity`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?severity=critical&status=new

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
severity=critical

The user-controlled value was:
critical`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new
  * Node Name: `https://localhost:8443/app/ (severity,status)`
  * Method: `GET`
  * Parameter: `status`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?severity=critical&status=new

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
status=new

The user-controlled value was:
new`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (severity,status,type)`
  * Method: `GET`
  * Parameter: `severity`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
severity=critical

The user-controlled value was:
critical`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (severity,status,type)`
  * Method: `GET`
  * Parameter: `status`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
status=new

The user-controlled value was:
new`
* URL: https://localhost:8443/app/%3Fseverity=critical&status=new&type=firewall
  * Node Name: `https://localhost:8443/app/ (severity,status,type)`
  * Method: `GET`
  * Parameter: `type`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?severity=critical&status=new&type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
type=firewall

The user-controlled value was:
firewall`
* URL: https://localhost:8443/app/%3Ftype=firewall
  * Node Name: `https://localhost:8443/app/ (type)`
  * Method: `GET`
  * Parameter: `type`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

https://localhost:8443/app/?type=firewall

appears to include user input in:
a(n) [option] tag [value] attribute

The user input found was:
type=firewall

The user-controlled value was:
firewall`


Instances: 12

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3


