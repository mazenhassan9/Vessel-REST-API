import requests

BASE = "http://127.0.0.1:5000/"
Access_Token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJmNzFjN2I2YS05OTExLTQyMmUtODEyMy0yMDc3NDc1Zjk1M2EiLCJleHAiOjE2MjU1MjU2MTl9.pqv6bBpT6WZNt0rWTAViQjQvU1nI_bIz_stOLwarVQE'
my_headers = {'x-access-token' : Access_Token}

#Test1
#response =requests.get(BASE + "Trades/",{'vessel_names':'Tsushima'})
#print(response.json())

#Test2
#response = requests.get(BASE+"No_barrels/",{'origin':'Belgium','destination':'Togo'})
#print(response.json())

#Test3
#response = requests.get(BASE+"/register",{'id':15,'username': 'Nosk','password':'asdfa','family':'Dirty'})
#print(response)

#Test4
response = requests.get(BASE+"/login",{'username': 'Nosk','password':'asdfa'})
print(response.json())

#Test5 Retrieve all the users
#response = requests.get(BASE+"/users")
#print(response)

#Test6
#response = requests.get(BASE+"/vessels_family",headers=my_headers)
#print(response.json())
#Test7
#response = requests.get(BASE+"/family_volume",headers=my_headers)
#print(response.json())
