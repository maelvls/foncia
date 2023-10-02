
With `graphqurl` (install it with `brew`):

```bash
export TOKEN=$(foncia token)
gq http://localhost:9090 -H "Authorization: bearer $TOKEN" -q 'query foo($accountUuid: EncodedID!) {
  coownerAccount(uuid: $accountUuid) {
    trusteeCouncil {
      missionIncidents {
        edges {
          node {
            ... {
              id
              number
              startedAt
              label
              status
            }
          }
        }
      }
    }
  }
}' -v "accountUuid=eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"
```

With `curl`:

```bash
curl 'https://myfoncia-gateway.prod.fonciamillenium.net/graphql' \
  -H "Authorization: Bearer $TOKEN" \
  --data-raw $'{"query":"query getCouncilMissionIncidents($accountUuid: EncodedID\u0021, $first: Int, $after: Cursor, $pageOptions: PageOptions) {
      coownerAccount(uuid: $accountUuid) {
        uuid
      trusteeCouncil {
          missionIncidents(first: $first, after: $after, pageOptions: $pageOptions) {
            totalCount
          pageInfo {
              ...pageInfo
            __typename
          }
          edges {
              node {
                ...missionIncident
              __typename
            }
            __typename
          }
          __typename
        }
        __typename
      }
      __typename
    }
  }

  fragment pageInfo on PageInfo {
      startCursor
    endCursor
    hasPreviousPage
    hasNextPage
    pageNumber
    itemsPerPage
    totalDisplayPages
    totalPages
    __typename
  }

  fragment missionIncident on MissionIncident {
      id
    number
    startedAt
    label
    status
    __typename
  }","variables":{"accountUuid":"eyJhY2NvdW50SWQiOiI2NDg1MGU4MGIzYjI5NDdjNmNmYmQ2MDgiLCJjdXN0b21lcklkIjoiNjQ4NTBlODAzNmNjZGMyNDA3YmFlY2Q0IiwicXVhbGl0eSI6IkNPX09XTkVSIiwiYnVpbGRpbmdJZCI6IjY0ODUwZTgwYTRjY2I5NWNlNGI2YjExNSIsInRydXN0ZWVNZW1iZXIiOnRydWV9"},"operationName":"getCouncilMissionIncidents"}'
```

Other example:

```bash
curl 'https://myfoncia-gateway.prod.fonciamillenium.net/graphql' \
  --data-raw '{"query":"query getAccounts {
      accounts {
        ...basicAccount
      __typename
    }
  }

  fragment basicAccount on Account {
      uuid
    number
    quality
    count {
        units
      buildings
      __typename
    }
    manager {
        id
      __typename
    }
    customer {
        ...customer
      __typename
    }
    hasRestrictedAccess
    ... on CoownerAccount {
        building {
          ...basicBuilding
        __typename
      }
      isTrusteeCouncilMember
      hasActiveCoOwnershipMandate
      showDalenysHeadband
      eReco {
          isSubscribed
        hasHistory
        __typename
      }
      hasEReleve
      hasAccessToGeneralAssembly
      __typename
    }
    ... on TenantAccount {
        building {
          ...basicBuilding
        __typename
      }
      __typename
    }
    ... on LandlordAccount {
        buildings {
          ...basicBuilding
        __typename
      }
      __typename
    }
    __typename
  }
  
  fragment customer on Customer {
      id
    number
    civility
    familyStatus
    firstName
    lastName
    email
    address {
        ...address
      __typename
    }
    birthDate
    phones {
        landline
      mobile
      __typename
    }
    noSnailMail
    contactPreferences {
        eventNotification {
          sms
        email
        postalMail
        __typename
      }
      litigationPrevention {
          sms
        email
        postalMail
        __typename
      }
      privilegedOffers {
          sms
        email
        postalMail
        __typename
      }
      myFonciaNews {
          sms
        email
        postalMail
        __typename
      }
      newsLetter {
          sms
        email
        postalMail
        __typename
      }
      __typename
    }
    confidentiality {
        personalData
      isFirstSubmit
      partnersOffersInformation
      offersInformation
      __typename
    }
    company {
        name
      siret
      address {
          ...address
        __typename
      }
      __typename
    }
    __typename
  }
  
  fragment address on Address {
      address1
    address2
    city
    zipCode
    countryCode
    __typename
  }
  
  fragment basicBuilding on Building {
      id
    name
    number
    address {
        ...address
      __typename
    }
    units {
        id
      __typename
    }
    __typename
  }","operationName":"getAccounts"}' \
```
