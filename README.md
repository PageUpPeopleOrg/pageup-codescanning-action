# pageup-codescanning-action
used to perform static security code scanning on .net repos


## Github workflow setup

If you don't already have a workflow in github you will need to add the below yaml to .github/workflows/main.yaml

```
  name: CI
  on:
    pull_request:
      branches: [ "main" ]

  jobs:
    build:
      runs-on: ubuntu-latest
      if: github.event.pull_request.draft == false

      steps:
        - name: 🛒 Checkout code
          uses: actions/checkout@v3

        - name: 🔐 PageUp Code Scanning Action
          uses: PageUpPeopleOrg/pageup-codescanning-action@main      
          if: always()
