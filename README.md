# untangle-tools
A place to put things I did for my untangle firewall

## custom captive portal

This is the reference implementation with a few changes:

1. A "site password" ... has to match the contents of 'password' file
2. Instead of asking for firstname/lastname just ask for 'name'

That's about it.

### How to use

1. checkout this repo
2. make a file 'password' with one line that is the password
3. `make custom.zip` and upload the result to your untangle
4. when guests are over, tell them the password they need to register


## Here is a screenshot

![Screenshot](screenshot.png?raw=true "Screenshot")


## Issues

* None of the fields are validated. Probaly will crash if user puts spaces or underscores in username for example.
  * This is same as original script.
* MVP of what I want is simpler
  * MVP is having a secret needed to log in **plus** a good faith ask for the user to say who they are.
  * Only need to ask two questions - what's the secret - and who do you claim to be?


## Thoughts to reduce friction

* Autogenerate userID and Password - no need to give to user.
* Record whatever they claim to be as First Name 
* Set expiration for user. Like the old quote "Guests, like fish, begin to smell after three days"
* Cookies that match expiration to avoid re-prompting
* Will need a user cull process - expired users remain in local db.

Alternative idea:

* No actual local user differentation - just site password and log what they give as 'name'
* Probably closer to MVP for occasional small quantities of visitors.  
* IP or MAC is likely good enough 

TODO: Based on the final item on the two above ideas ... determine if there is any benefit to having user native in untangle UI vs. needing to lookup.  

Alternative is probably the better solution given small number of users and much smaller expectation of needing to investiage issues.



