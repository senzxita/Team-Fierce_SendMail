<p align="center">
  <a href="" rel="noopener">
 <!-- <img width=200px height=200px src="https://i.imgur.com/6wj0hh6.jpg" alt="Project logo"></a> -->
 <img width=200px height=200px src="" alt="SendMail"></a>
</p>

<h3 align="center">SendMail</h3>

<div align="center">

[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![GitHub Issues](https://img.shields.io/github/issues/gblend/Team-Fierce_SendMail.svg)](https://github.com/gblend/Team-Fierce_SendMail/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/gblend/Team-Fierce_SendMail.svg)](https://github.com/gblend/Team-Fierce_SendMail/pulls)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](/LICENSE)

</div>

---

<p align="center"> SendMail is a microservice project to aid the process of sending email notifications to individual/multiple individuals/mailing list subscribers seamless.
    <br> 
</p>

## 📝 Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Built Using](#built_using)
- [Authors](#authors)
- [Acknowledgments](#acknowledgement)

## 🧐 About <a name = "about"></a>

SendMail is a microservice project to aid the process of sending email notifications to mailing list subscribers. SendMail offers the options of sending emails in plain text format or using html template. SendMail components are decoupled in functionality.



## 🏁 Getting Started <a name = "getting_started"></a>

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

To run the software locally you need <strong>Python interpreter</strong> (version 3.xx) installed on your machine.

```
www.python.org
```

-To start the system navigate to the project folder, 
<br>
-Open the terminal/cmd and run => <strong>pip install -r requirements.txt</strong> (To install dependencies)
<br>
-On the terminal/cmd execute => <strong>python server.py</strong>
<br>
-Open the link of the local server on the terminal in the browser,
<br>
-Enter the endpoints specified with numbers below, along with access-token (x-acess-tokens) in the request <strong>Headers</strong> to access the different actions

The SendMAil API includes the following endpoints:
 <br><br>
 <img width=1000 height=600px src="https://github.com/gblend/Team-Fierce_SendMail/blob/master/static/images/documentation_ui.PNG?raw=true" alt="Project logo"></a>
<br><br>
=>   <strong>/v1/auth/register</strong>
    => This endpoint is used to register an account, through which access-token will be obtained for accessing certain resource.
<br><br>
=>   <strong>/v1/auth/login</strong>
    => This endpoint is used to login registered user in other to obtain access-token for authentication
<br><br>
=>   <strong>/v1/auth/users</strong>
    => This endpoint display the list of all registered users
<br><br>
=>   <strong>/v1/documentation</strong>
    => This endpoint responds with a json version of all endpoint documentation
<br><br>
=>   <strong>/v1/configure</strong>
    @Todo ...
<br>
1. <strong>/v1/sendmail/people</strong> 
   => This endpoint responds to a request for /v1/sendmail/people with the complete lists of people
<br><br>
2. <strong>/v1/sendmail/people/{email}</strong>
    => This endpoint responds to a request for /v1/sendmail/people/{email}
    with the details of a person or delete action status
    :param email:   email address of person to get details about or delete
<br><br>
3. <strong>/v1/sendmail/people/{person}</strong>
    => This endpoint creates a new person in the people structure
    based on the passed in person data
    :param person:   person object to create
<br><br>
4. <strong>/v1/sendmail/people/{email, people}</strong>
    => This endpoint updates an existing person in the people structure
<br><br>
5. <strong>/v1/sendmail</strong>
    => This endpoint sends a plain email to subscriber/subscribers
<br>
6. <strong>/v1/sendmailwithtemplate</strong>
    => This endpoint sends a template email to subscriber/subscribers


## 🎈 Usage <a name="usage"></a>

To checkout the endpoints, navigate to the endpoints urls as specified at [Getting Started](#getting_started) section
<br>
<strong>/v1/sendmail/interface</strong>
<br>
<img width=1000 height=600 src="https://github.com/gblend/Team-Fierce_SendMail/blob/master/static/images/interface.PNG?raw=true" alt="Interface img"/><br>

## ⛏️ Built Using <a name = "built_using"></a>

- [Python](https://www.python.org/) - Language
- [Flask](https://flask.palletsprojects.com/) - Web Framework
- [jQuery](https://jquery.com/) - jQuery

## ✍️ Authors <a name = "authors"></a>

- [@Team-Fierce](https://github.com/gblend/Team-Fierce_SendMail) - Idea & Initial work


## 🎉 Acknowledgements <a name = "acknowledgement"></a>

- Hat tip to everyone whose code was used.

