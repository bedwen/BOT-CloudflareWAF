# **Clapi**

**Clapi is a Python bot that communicates with Cloudflare WAF through its API, allowing you to add and delete rules and perform various functions.**

This bot was created with the aim of learning about Cloudflare WAF and improving my Python programming skills.

It was developed with the guidance of artificial intelligence.

---
# **Functions**
```
- 0-Under Attack Mode
- 1-List Rules
- 2-Delete Rule
- 3-Block IP Address
- 4-Bulk Block IPs (from file)
- 5-Bulk Unblock IPs (from file)
- 6-Unblock IP (Fast)
- 7-IP Threat Intelligence
- 8-Live Logs
- 9-Exit
```
---
**[0] Under Attack Mode**

When the site is under attack, we do not need to access the website to activate Under Attack Mode. Instead, we can 
enable this mode directly by selecting the relevant function through the terminal.

This approach allows us to respond quickly when access to the management panel is unavailable during an attack, thereby 
improving the overall security of our web application.

---
**[1] List Rules**

List the rules; first, three options appear in front of us:

- 1-Custom Rules
- 2-Rate-Limiting Rules
- 3-IP Block Rules


- Custom Rules, lists the rules we have created.
- Rate-Limiting Rules, lists the rules we use to limit the number of requests and bot requests.
- IP Block Rules, lists the IP addresses we have blocked.

---
**[2] Delete Rule**

The Delete Rule function allows us to select a rule from the Custom, Rate-Limiting, or IP Block rules and delete the 
selected rule.

---
**[3] Block IP Address**

With this function, we can directly block the IP address we enter.

---
**[4-5] Bulk Block - Unblock IPs (from file)**

With these two functions, we can bulk-block IP addresses from a TXT file and, likewise, bulk-unblock them.

---
**[7] IP Threat Intelligence**


This function shows us whether the IP address we enter is dangerous, which country the request originated from, and its 
report status. It can be considered a basic form of IP intelligence.

---
**[8] Live Logs**

This function retrieves the last 15 log entries recorded in the Firewall.

---
**[9] Exit**

This option allows us to exit the bot.This option allows us to exit the bot.

---
# Installation

**Clone the repository**

- `git clone https://github.com/bedwen/clapi.git`
- `cd clapi`

**Install pipx**

**If `pipx` is not already installed, install it using the instructions below.**
- Linux (Debian/Ubuntu)
  
  - `sudo apt install pipx`
  - `pipx ensurepath`
  
- macOS:

  - `brew install pipx`
  - `pipx ensurepath`

- Windows:

  - `py -m pip install --user pipx`
  - `py -m pipx ensurepath`

**Install the tool**
From the project directory, run:
- `pipx install .`

**Set the environment variables**

- Use the env.example file as a template to create a .env file, and populate its contents according to the env.example 
file
- Cloudflare token: Create an API token from your Cloudflare account and give the token permission to manage 
firewall/rules and zone settings.

**Run the tool**
- `clapi`
---
