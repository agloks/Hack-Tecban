# Readme file for TPP233 

## Client Details 
 clientID=bec537c2-df01-4f15-9881-16f3865a507f 
 clientSecret=45f64954-fde8-4cb2-aa83-d0b2bb928516 

## Organisation Details 
 orgName=TPP233 
 orgID=4de110f3-8733-4995-82c3-f0eee3728f6d 

## Software Details 
 softwareName=TPP233 
 softwareID=059fd4f9-2d80-435d-b165-68e82382bd59 

## Cert KID Details 
 transportKID=B7wakDQ6xBBivIDNmEVqkrHAahUjlSTvuUHAI0jxuGM 
 signingKID=MWMxjflb4VIIwRB5jliLVQQfxpG06H-0R2TbrniJkn0 

## Cert Pem Details 
 transportPEM=https://tecban-uat-us-east-1-keystore.s3.amazonaws.com/4de110f3-8733-4995-82c3-f0eee3728f6d/059fd4f9-2d80-435d-b165-68e82382bd59/B7wakDQ6xBBivIDNmEVqkrHAahUjlSTvuUHAI0jxuGM.pem 
 signingPEM=https://tecban-uat-us-east-1-keystore.s3.amazonaws.com/4de110f3-8733-4995-82c3-f0eee3728f6d/059fd4f9-2d80-435d-b165-68e82382bd59/MWMxjflb4VIIwRB5jliLVQQfxpG06H-0R2TbrniJkn0.pem 

## Server Details 
 Well Known Endpoint=https://auth2.tecban-sandbox.o3bank.co.uk/.well-known/openid-configuration 
 Token Endpoint=https://as2.tecban-sandbox.o3bank.co.uk/token 
 Resource Endpoint=https://rs2.tecban-sandbox.o3bank.co.uk 
 Auth Endpoint=https://auth2.tecban-sandbox.o3bank.co.uk/auth 

 ## User & Account Details 
 [
  {
    "username": "team233b2u1",
    "password": "259282",
    "accounts": [
      {
        "accountNumber": "02233001001"
      },
      {
        "accountNumber": "02233001002"
      },
      {
        "accountNumber": "02233001003"
      }
    ]
  },
  {
    "username": "team233b2u2",
    "password": "214969",
    "accounts": [
      {
        "accountNumber": "02233002001"
      },
      {
        "accountNumber": "02233002002"
      },
      {
        "accountNumber": "02233002003"
      }
    ]
  },
  {
    "username": "team233b2u3",
    "password": "842626",
    "accounts": [
      {
        "accountNumber": "02233003001"
      },
      {
        "accountNumber": "02233003002"
      },
      {
        "accountNumber": "02233003003"
      }
    ]
  },
  {
    "username": "team233b2u4",
    "password": "773162",
    "accounts": [
      {
        "accountNumber": "02233004001"
      },
      {
        "accountNumber": "02233004002"
      },
      {
        "accountNumber": "02233004003"
      }
    ]
  },
  {
    "username": "team233b2u5",
    "password": "549565",
    "accounts": [
      {
        "accountNumber": "02233005001"
      },
      {
        "accountNumber": "02233005002"
      },
      {
        "accountNumber": "02233005003"
      }
    ]
  }
] 

## Tip for testing in postman 
 In postman settings - certificates tab - add the transport cert and key for the rs and token endpoints 

