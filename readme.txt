=== Analytical Spam Filter ===
Contributors: dalesandro
Tags: spam, antispam, anti-spam, spam blocker, spam filter, block spam, comment filter, comment spam, security, protection
Requires at least: 5.3
Tested up to: 6.6
Requires PHP: 7.1
Stable tag: 1.0.13
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block WordPress comment spam, trackback spam, and pingback spam through intelligent analytics instead of interactive challenge response tests.

== Description ==
The **Analytical Spam Filter** plugin for WordPress blocks comment, trackback, and pingback spam. It uses multiple spam detection methods without challenging the user with obstacles such as captchas, math problems, etc. and it does not rely on external services or APIs. This is a low overhead plugin that begins blocking spam as soon as it is activated. It is compatible with caching plugins as long as the user has JavaScript enabled. The plugin blocks spam submitted through the default WordPress comment form only.

Logic is used to identify spam comment submissions. No user interaction is required. The spam blocking mechanisms work transparently behind the scenes. Most visitors will require longer than a few seconds to read a post and add a meaningful comment so any comments submitted within a short time threshold are identified as spam. Comments containing a large number of links are flagged as spam. The plugin uses an encrypted code and a honeypot to filter robotic submissions. All field names added by the plugin are randomized to prevent detection based on a source code signatures.

Configuration options include:

* Enable Cache Compatibility (requires JavaScript)
* Add spam to WordPress queue or block completely
* Send diagnostic information to site administrator
* Automatically compatible with the **Micro Contact Form** plugin to block spam messages.

Blocking options include:

* Honeypot Trap
* Randomized Internal Field Names
* Timestamps (minimum and maximum entry time)
* Aggressively check for excessive URLs
* Check if JavaScript is enabled
* Automatically block repeated spam from IP
* Automatically block repeated spam based on content
* Require User Agent string
* Require Referer
* Block Trackbacks
* Block Pingbacks

== Installation ==
1. Install Analytical Spam Filter through the WordPress.org plugin repository or by uploading the .zip file using the Admin -> Plugins -> Add New function.
2. Activate Analytical Spam Filter on the Admin -> Plugins screen.
3. Customize settings on the Admin -> Settings -> Analytical Spam Filter screen.

Uninstall
1. Deactivate the plugin on the Admin -> Plugins screen. All plugin files and settings will be retained.
2. Delete the plugin on the Admin -> Plugins screen. This deletes the plugin files, plugin database tables, and all plugin settings stored in the database.

== Frequently Asked Questions ==
= Why did I still receive a spammy comment? =

The plugin uses a number of methods to block spam comments without requiring additional human interaction (captchas). While these detection methods significantly reduce automated spam, they may not block all low quality, human entered comments. Use the diagnostic e-mails to establish the appropriate settings and thresholds to block the most spam. The plugin only blocks spam comments submitted through the default WordPress comment form.

= Does it work with other comment plugins? =

No. The plugin only blocks spam comments submitted through the default WordPress comment form.

= Timestamp blocking is not working. =

If the site is using a caching plugin, verify that the Analytical Spam Filter option for cache compatibility is enabled. This option requires that the user has JavaScript enabled. Even if a caching plugin is not used, enabling this option adds another detection measure since bots typically do not have JavaScript enabled.

== Screenshots ==
1. Analytical Spam Filter admin screen - General Settings.
2. Analytical Spam Filter admin screen - Basic Blocking Techniques.
3. Analytical Spam Filter admin screen - Timestamp Blocking.
4. Analytical Spam Filter admin screen - URL Blocking.
5. Analytical Spam Filter admin screen - IP Blocking.
6. Analytical Spam Filter admin screen - Content Blocking.

== Changelog ==
= 1.0.13 =
* Added setting to send diagnostic notifications for valid submissions only.

= 1.0.12 =
* IP blocking enhanced for reverse proxies.

= 1.0.11 =
* Corrects a compatibility issue with the Micro Contact Form plugin

= 1.0.10 =
* Strengthened timestamp capability to measure active form entry time

= 1.0.9 =
* Corrected styles for default themes

= 1.0.8 =
* Simplified styling for honeypot fields

= 1.0.7 =
* Corrected issue with gallery block formatting due to hidden field style

= 1.0.6 =
* Corrected warning for undefined variable

= 1.0.5 =
* Corrected missing parameter during initial checks for plugin database tables

= 1.0.4 =
* Updated notification wording when timestamp is invalid

= 1.0.3 =
* Strengthened and simplified URL counting capability
* Strengthened IP sanitization

= 1.0.2 =
* Added settings to stop administrator notifications for repeated spam submissions

= 1.0.1 =
* Minor changes to improve code readability and internationalization

= 1.0.0 =
* Initial Release