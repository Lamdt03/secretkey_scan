# Installing

download gitleaks at https://github.com/gitleaks/gitleaks/releases </br>
download trufflehog at https://github.com/trufflesecurity/trufflehog/releases

# Output
## Folder structure
```
 ── final                   
    ├── gitRepo                   #git repository clone
    |    ├── org1 
    |        ├── repo1
    |        ├── repo2
    |        ├── repo3
    |        ...
    |    ├── org2 
    |        ├── repo1
    |        ├── repo2
    |        ├── repo3
    |        ...    
    |    ...                         
    ├── secretReport                #secret key found
        ├── gitleaks                #secret key found by gitleaks
        |    ├── gitRepo  
        |        ├── org1 
        |        |   ├── repo1.json     #report about secret key found
        |        |   ├── repo2.json
        |        |   ├── repo3.json
        |        |    ...
        |        ├── org2 
        |            ├── repo1.json
        |            ├── repo2.json
        |            ├── repo3.json
        |            ...
        |        ...
        ├── trufflehog              #secret key found by trufflehog  
        |         ├── gitRepo  
        |             ├── org1 
        |             |   ├── repo1
        |             |   |   ├── repo1.json    #report about secret key found
        |             |   ├── repo2
        |             |   |   ├── repo2.json
        |             |   ├── repo3
        |             |   |   ├── repo3.json
        |             |   |    ...
        |             ├── org2 
        |                 ├── repo1.json
        |                 ├── repo2.json
        |                 ├── repo3.json
        |                    ...
        |                ...
        ├── repo1.json                  ##report about secret key found by gitleaks ||truffehog
        ├── repo2.json
        ├── repo3.json     
        ...
```

## File structure
```
  email: "tunglamadhp2403@gmail.com",
  commit: "3f6721a545b55910ecf69739fd00f52c4d1ebf16",
  file: "src/main/java/server/database/database.java",
  timestamp: "2024-01-13 09:10:02",
  message: " init",
  secret: "\"contales2403\"",
  location: "src/main/java/server/database/database.java:20:34",
  description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
  isVerified: true,
  detectedBy: "trufflehog + gitleaks"
```