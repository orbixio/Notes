osTicket is a web application that is highly maintained and serviced. If we look at the CVEs found over decades, we will not find many vulnerabilities and exploits that osTicket could have. This is an excellent example to show how important it is to understand how a web application works. Even if the application is not vulnerable, it can still be used for our purposes

 If the company set up their helpdesk software to correlate ticket numbers with emails, then any email sent to the email we received when registering, 940288@inlanefreight.local, would show up here. With this setup, if we can find an external portal such as a Wiki, chat service (Slack, Mattermost, Rocket.chat), or a Git repository such as GitLab or Bitbucket, we may be able to use this email to register an account and the help desk support portal to receive a sign-up confirmation email.  

### Enumeration

To determine the version of osTicket in use, try visiting BASE_URL/setup/ (like http://doma.in/setup/) to determine server version.

Collect usernames: https://github.com/initstring/linkedin2username


### Attacking

osTicket version 1.14.1 suffers from CVE-2020-24881 which was an SSRF vulnerability. 

```
CVE-2019-14748
CVE-2019-14749
CVE-2019-14750
CVE-2020-16193
CVE-2020-24881
```

## Vulnerability Matrix
| Vulnerable Version(s) | Attack Type | Severity | Proof of Concept | CVE/GitHub Commit |
| --------------------- | ----------- | -------- | ---------------- | ----------------- |
| < 1.15.8, 1.16.x < 1.16.3 | Session Fixation | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/85a76f403a3a116176d0798f39a4c430181d8364) |
| < 1.15.8, 1.16.x < 1.16.3 | Content Injection | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/45b6cf2e6ad04fa248b18d4d3fbd10872190cfcf) |
| < 1.15.8, 1.16.x < 1.16.3 | Authentication Bypass | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/01a378f6400f013a5deda86dd2cb82d7ec3ffad8) |
| < 1.15.8, 1.16.x < 1.16.3 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/334934ec6b4363ea30a2a873b4db017c3734ab65) |
| < 1.15.8, 1.16.x < 1.16.3 | Reflected XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/a5c4d931e3b47874b07ab388b426f9bd186f7a24) |
| < 1.14.8, 1.15.x < 1.15.4 | SQL Injection | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/e28291022e662ffa754e170c09cade7bdadf3fd9) |
| < 1.14.8, 1.15.x < 1.15.4 | Information Disclosure | 5.3 | [Link](commit-vulnerabilities/86165c/) | [Commit](https://github.com/osTicket/osTicket/commit/86165c2e6b847d910bc3fc93444d18b6173215de) |
| < 1.14.8, 1.15.x < 1.15.4 | Blind SSRF/CSRF | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/1c6f98e62fb12b74a56b3f2f730da61ccd3004f2) |
| < 1.14.8, 1.15.x < 1.15.4 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/4b4da5bee78b4241654571e1698eec0d42d79dc9) |
| < 1.14.8, 1.15.x < 1.15.4 | Email Injection | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/7c5c584f95b96e92b872e54d4fe2a16546a7a8cf) |
| < 1.14.8, 1.15.x < 1.15.4 | XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/4a8d3c8b0a2df3f3132370e6da14c150a3b96b4f) |
| < 1.14.8, 1.15.x < 1.15.4 | XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/b01c6a2b976b7124b50a4a6ef5bafeef7bde4889) |
| < 1.14.7, 1.15.x < 1.15.3 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/68dcaa2e54e763912097a48cf8e10faaa6081096) |
| < 1.14.7, 1.15.x < 1.15.3 | Reflected XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/fd560df05868b770e113ec022c77f25d9df5e011) |
| < 1.14.6, 1.15.x < 1.15.2 | XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/8d956e0f46b33d2f5b28effa30ed8ca06568bb91) |
| < 1.14.6, 1.15.x < 1.15.2 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/25e6d123ac182fc9422aa6b63ffaf1e294ee14ac) |
| < 1.14.5, 1.15 | Broken Access Control | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/5972fe819c2e0c4653c88d1042c10874bbae1dff) |
| < 1.14.3 | Blind SSRF/CSRF | 7.5 | [Link](cves/CVE-2020-24881/) | [CVE-2020-24881](https://www.cvedetails.com/cve/CVE-2020-24881/) |
| < 1.14.3 | XSS | 4.3 | N/A | [CVE-2020-24917](https://www.cvedetails.com/cve/CVE-2020-24917/) |
| < 1.14.3 | Stored XSS | 3.5 | [Link](cves/CVE-2020-16193/) | [CVE-2020-16193](https://www.cvedetails.com/cve/CVE-2020-16193/) |
| < 1.14.3 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/d2491c1f2510e55fd37140ecfafa43d6ee19a93d) |
| < 1.14.3 | Stored XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/518de223933eab0c5558741ce317f36958ef193d) |
| < 1.12.6, 1.14.1 | Stored XSS | 5.0 | N/A | [ExploitDB](https://www.exploit-db.com/exploits/48413) / [Commit](https://github.com/osticket/osticket/commit/fc4c8608fa122f38673b9dddcb8fef4a15a9c884) |
| < 1.12.6, 1.14.1 | Stored XSS | 4.3 | N/A | [ExploitDB](https://www.exploit-db.com/exploits/48524) / [Commit](https://github.com/osTicket/osTicket/commit/6c724ea3fe352d10d457d334dc054ef81917fde1) |
| < 1.12.6, 1.14.1 | Stored XSS | 4.3 | N/A | [ExploitDB](https://www.exploit-db.com/exploits/48525) / [Commit](https://github.com/osTicket/osTicket/commit/d54cca0b265128f119b6c398575175cb10cf1754) |
| < 1.12.6, 1.14.1 | XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/f705001ae4e856847f39517721df7f16ef4fdcc7) |
| < 1.12.6, 1.14.1 | XSS | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/de41aeb14b2ec01e481d97a97eb56b7f52c09aa2) |
| < 1.12.5 | Arbitrary Method Invocation | Unconfirmed | N/A | [Commit 1](https://github.com/osTicket/osTicket/commit/4dfb77caf2b77b4b996de6a441a75e409ec1dd12), [Commit 2](https://github.com/osTicket/osTicket/commit/d3e643d9d27cea6b1cfeadcf49403d7d14d1d4da) |
| < 1.12.4 | Authentication Bypass | 7.2 | N/A | [Commit](https://github.com/osTicket/osTicket/commit/a9834d88f7b41dae23173b894156630bca73c545) |
| < 1.12.4 | Unrestricted File Upload | Unconfirmed | N/A | [Commit](https://github.com/osTicket/osTicket/commit/9f4fbc2708cc14f88bc34f369e54930160c2f0c9) |
| < 1.12.4 | Remote Code Execution | Unconfirmed | N/A | [Commit 1](https://github.com/osTicket/osTicket/commit/6e039ab7cd6e182e727d45f2e5b810257452ce97), [Commit 2](https://github.com/osTicket/osTicket/commit/57721def6a63345b0a031944dd18bd7f518940ef) |
| < 1.10.7, 1.11, 1.12 | CSV Injection | 6.8 | [Link](cves/CVE-2019-14749/) | [CVE-2019-14749](https://www.cvedetails.com/cve/CVE-2019-14749/) |
| < 1.10.7, 1.11, 1.12 | Stored XSS | 4.3 | [Link](cves/CVE-2019-14750/) | [CVE-2019-14750](https://www.cvedetails.com/cve/CVE-2019-14750/) |
| < 1.10.7, 1.11, 1.12 | Stored XSS | 3.5 | [Link](cves/CVE-2019-14748/) | [CVE-2019-14748](https://www.cvedetails.com/cve/CVE-2019-14748/) |
