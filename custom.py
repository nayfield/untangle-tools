from uvm.settings_reader import get_nodeid_settings
from mod_python import apache
from mod_python import util
from uvm import Uvm
import urllib2
import cgi
import simplejson as json
import os

# When you include a custom.py file in your custom captive portal zip file
# you get full control over the capture and authentication process.

# When the captive portal intercepts traffic and a capture page needs to
# be displayed, our main handler will call your index function and will
# pass you a bunch of parameters you can use to build your custom page:
#
# req - this is the apache request object
# rawpath - this is the full path to where the custom files are stored
#   and it will include the trailing backslash
#   e.g.: /usr/share/untangle/web/capture/custom_6/
# webpath - this is the relative path from which images and other
#   linked content can be specified and includes trailing backslash
#   e.g.: /capture/custom_6/
# appid - each instance of captive portal is assigned a unique appid
#   value that you MUST include as a parameter to the custom_handler
#   so the mod_python scripts know which instance to work with
#   e.g.: 6
# host - this is the host from the original HTTP request that resulted
#   in the captive page display
#   e.g.: www.yahoo.com
# uri - this is the path from the original HTTP request that resulted
#   in the captive page display
#   e.g.: /some/page/or/something/content.html
#
# In our example below we create a simple page with a form where the hotel
# guest can enter their name and room number.  Note that the POST handler
# is set to the parent captive portal handler, and we pass the appid so it
# knows which instance of captive portal is calling.  Our example doesn't
# need the rawpath but we do use the webpath to include a spiffy image
# and page icon.  We hide the original host and uri in the form so we can
# redirect the user to their original destination after authentication.

def index(req,rawpath,webpath,appid,host,uri,errorText=None):

    page = "<HTML><HEAD>"
    page += "<META http-equiv='Content-Type' content='text/html; charset=UTF-8' />"
    page += "<SCRIPT type='text/javascript'> function FocusOnInput() { document.getElementById('guest').focus(); } </SCRIPT>"
    page += "<LINK REL='icon' TYPE='image/png' HREF='" + webpath + "pageicon.png'>"
    page += "<TITLE>Account registration</TITLE>"
    page += "</HEAD><BODY ONLOAD='FocusOnInput()'>"
    page += "<H1>Account registration</H1>"
    if errorText and len(errorText) > 0:
        page += "<P><H2><FONT color=\"red\">%s</font></H2></P>" % errorText
    page += "<FORM AUTOCOMPLETE='OFF' METHOD='POST' ACTION='/capture/handler.py/custom_handler?appid=" + appid + "'>"
    page += "<TABLE BORDER=0 CELLPADDING=8>"
    page += "<TR><TD>Username</TD><TD><INPUT WIDTH=80 TYPE='text' NAME='username' ID='username'></INPUT></TD></TR>"
    page += "<TR><TD>Password</TD><TD><INPUT WIDTH=80 TYPE='password' NAME='pwd' ID='pwd'></INPUT></TD></TR>"
    page += "<TR><TD>Email</TD><TD><INPUT WIDTH=80 TYPE='text' NAME='email' ID='email'></INPUT></TD></TR>"
    page += "<TR><TD>Name</TD><TD><INPUT WIDTH=80 TYPE='text' NAME='firstname' ID='firstname'></INPUT></TD></TR>"
    page += "<TR><TD>Registration Password</TD><TD><INPUT WIDTH=80 TYPE='text' NAME='regpass' ID='regpass'></INPUT></TD></TR>"
    page += "</TABLE>"
    page += "<H2>Get the registration password from somebody who lives here</H2>"
    page += "<INPUT TYPE='hidden' NAME='host' ID='host' VALUE='" + host + "'></INPUT>"
    page += "<INPUT TYPE='hidden' NAME='uri' ID='uri' VALUE='" + uri + "'></INPUT>"
    page += "<P><BUTTON TYPE='submit' NAME='submit' ID='submit' TITLE='Register' value='Register'>Register</BUTTON>"
    page += "&nbsp;&nbsp;&nbsp;&nbsp;<BUTTON TYPE='submit' NAME='submit' ID='submit' TITLE='Login' value='Login'>Login</BUTTON></P>"
    page += "</FORM>"
    page += "</BODY></HTML>"

    req.content_type = "text/html"
    req.write(page)

# When our parent post handler gets the form defined above, it will call
# your handler function passing many of the same arguments described above.

def handler(req,rawpath,webpath,appid):

    # get the network address of the client
    address = req.get_remote_host(apache.REMOTE_NOLOOKUP,None)

    # grab the form fields from the post data
    uname=req.form['username'].value
    email = req.form['email'].value
    pwd = req.form['pwd'].value
    host = req.form['host'].value
    uri = req.form['uri'].value
    action = req.form['submit'].value
    fn = req.form['firstname'].value
    rp = req.form['regpass'].value

    # first we get the uvm context
    context = Uvm().getUvmContext()
    if not context:
        raise Exception("The uvm context could not be obtained")

    # now we use the uvm context to get the captive portal node instance
    # note that we pass the appid so we get a reference to the correct instance
    capture = context.nodeManager().node(long(appid))
    if not capture:
        raise Exception("The uvm node manager could not locate the capture node instance")

    # we also want the node settings so we can check for a custom redirect target
    settings = get_nodeid_settings(long(appid))
    if (settings == None):
        raise Exception("Unable to load capture node settings")

    # General Note: While this custom page is active be aware that admin actions in the WebUI on Local Directory can overwrite
    # new users created by this page if those users are created while the admin is performing actions in the WebUI

    actions=['Register','Login']
    if action in actions:
        localDirectory = context.localDirectory()
        if not localDirectory:
            raise Exception("The uvm node manager could not locate the local directory instance")
        if action == 'Register':
            fp = os.path.dirname(os.path.realpath(__file__))
            f=open(os.path.join(fp, "password"), "r")
            pw=f.readline().strip()
            f.close()
            if rp != pw:
                return index(req,rawpath,webpath,appid,host,uri,"That's not the right password !")

            if email and len(email.strip()) > 0 and pwd and len(pwd.strip()) > 0 and uname and len(uname.strip()) > 0:
                userToRegister={"email": "%s"%email, "firstName":"%s"%fn, "password":"%s"%pwd, "username":"%s"%uname, "javaClass":"com.untangle.uvm.LocalDirectoryUser"}
                if not localDirectory.userExists(userToRegister):
                    localDirectory.addUser(userToRegister)
                    capture.userAuthenticate(address, uname, pwd)
                else:
                    return index(req,rawpath,webpath,appid,host,uri,"User already exists !")
            else:
                return index(req,rawpath,webpath,appid,host,uri,"Username, password and email must be set !")
        else:
            if not localDirectory.authenticate(uname,pwd):
                return index(req,rawpath,webpath,appid,host,uri,"Authentication failed !")
            else:
                capture.userAuthenticate(address,uname,pwd)

        # if a redirect URL is configured we send the user to that location
        if (len(settings['redirectUrl']) != 0) and (settings['redirectUrl'].isspace() == False):
            target = str(settings['redirectUrl'])
        # no redirect URL is configured so send the user to the originally requested page
        else:
            # if the host or uri are empty we just return a simple success page
            if ((host == 'Empty') or (uri == 'Empty')):
                page = "<HTML><HEAD><TITLE>Login Success</TITLE></HEAD><BODY><H1>Login Success</H1></BODY></HTML>"
                return(page)
            else:
                target = str("http://" + host + urllib2.unquote(uri).decode('utf8'))

        util.redirect(req, target)

    else:
       index(req, rawpath, webpath, appid, host, uri)

