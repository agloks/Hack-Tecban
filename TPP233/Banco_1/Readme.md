# Readme file for TPP233 

## Client Details 
 clientID=bad8b4d9-207f-46c5-9251-841959a1b026 
 clientSecret=f95aa80d-1986-47b8-9666-8dd3644e1317 

## Organisation Details 
 orgName=TPP233 
 orgID=7788bb48-1030-4d03-ba10-9ad95e490d20 

## Software Details 
 softwareName=TPP233 
 softwareID=28360139-4f21-469c-af30-dccac12b7abb 

## Cert KID Details 
 transportKID=Mp_ULZeEcE19BuBmJuVHYAWLuAjYKpcTP15bYDP5DMw 
 signingKID=yS5mr63PfJG8i0gsYthzvc_9MFE5v9VkMIqnYvlkNec 

## Cert Pem Details 
 transportPEM=https://tecban-uat-us-east-1-keystore.s3.amazonaws.com/7788bb48-1030-4d03-ba10-9ad95e490d20/28360139-4f21-469c-af30-dccac12b7abb/Mp_ULZeEcE19BuBmJuVHYAWLuAjYKpcTP15bYDP5DMw.pem 
 signingPEM=https://tecban-uat-us-east-1-keystore.s3.amazonaws.com/7788bb48-1030-4d03-ba10-9ad95e490d20/28360139-4f21-469c-af30-dccac12b7abb/yS5mr63PfJG8i0gsYthzvc_9MFE5v9VkMIqnYvlkNec.pem 

## Server Details 
 Well Known Endpoint=https://auth1.tecban-sandbox.o3bank.co.uk/.well-known/openid-configuration 
 Token Endpoint=https://as1.tecban-sandbox.o3bank.co.uk/token 
 Resource Endpoint=https://rs1.tecban-sandbox.o3bank.co.uk 
 Auth Endpoint=https://auth1.tecban-sandbox.o3bank.co.uk/auth 

 ## User & Account Details 
 [
  {
    "username": "team233b1u1",
    "password": "359535",
    "accounts": [
      {
        "accountNumber": "01233001001"
      },
      {
        "accountNumber": "01233001002"
      },
      {
        "accountNumber": "01233001003"
      }
    ]
  },
  {
    "username": "team233b1u2",
    "password": "766403",
    "accounts": [
      {
        "accountNumber": "01233002001"
      },
      {
        "accountNumber": "01233002002"
      },
      {
        "accountNumber": "01233002003"
      }
    ]
  },
  {
    "username": "team233b1u3",
    "password": "454178",
    "accounts": [
      {
        "accountNumber": "01233003001"
      },
      {
        "accountNumber": "01233003002"
      },
      {
        "accountNumber": "01233003003"
      }
    ]
  },
  {
    "username": "team233b1u4",
    "password": "451565",
    "accounts": [
      {
        "accountNumber": "01233004001"
      },
      {
        "accountNumber": "01233004002"
      },
      {
        "accountNumber": "01233004003"
      }
    ]
  },
  {
    "username": "team233b1u5",
    "password": "519334",
    "accounts": [
      {
        "accountNumber": "01233005001"
      },
      {
        "accountNumber": "01233005002"
      },
      {
        "accountNumber": "01233005003"
      }
    ]
  }
] 

## Tip for testing in postman 
 In postman settings - certificates tab - add the transport cert and key for the rs and token endpoints 

