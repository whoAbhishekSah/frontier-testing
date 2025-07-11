## Usage

`go run main.go`

### Scratch

```sh
# get org as superuser
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{"id":"org-uuid"}'

# get org as a new user
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{"id":"org-uuid"}'

# send invite using UI

# accept invite using User Cookie
curl --location 'http://localhost:8000/v1beta1/organizations/org-uuid/invitations/invite-id/accept' \
--header 'Content-Type: application/json' --header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{}'

# Get org using user cookie
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{"id":"org-uuid"}'

# List all users with Superuser access token
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"page_size": 10,"page_number": 1}'

# Get org with serviceuser access token(pub/pvt key pair)
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"id":"org-uuid"}'

# Get org with serviceuser access token(pub/pvt key pair)
curl --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"id":"eef38056-3b17-4f40-85c7-72c10cc53472"}'

curl -v  --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"id":"org-uuid"}'

curl -v  --location 'http://localhost:8002/raystack.frontier.v1beta1.FrontierService/GetOrganization' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{"id":"org-uuid"}'

curl --location 'http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"page_size": 10,"page_number": 1}'

curl --location 'http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"page_size": 10,"page_number": 1}'

curl -v --location 'http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'authorization: Bearer xyz'\
--data '{"page_size": 10,"page_number": 1}'

curl -v --location 'http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Cookie: sid=xyz' \
--data '{"page_size": 10,"page_number": 1}'
```
