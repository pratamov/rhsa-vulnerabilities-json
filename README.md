# README

## About

This project is fetching RHSA Vulnerability from `http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml` and transform into json format.
This program runs in python3

## How to run

### Prerequisites
- Python 3
- Requests package (https://pypi.org/project/requests/)

### Run

```
python app.py
```
These will generate file `com.redhat.rhsa-all.json`

## How it's works

This is pseudo algorithm to show the script flows
1. Download the document `http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml` and parse into XML object
2. Fetch the `rpminfo_object`, `rpminfo_state` and `rpminfo_test` then transform into format about like this:

```
{
    "<rpminfo_test ID>": {
        "object": <object name as string>,
        "state": [
            ["<state_name>", "", "<state_operation>", <state_value>]
        ]
    }
}
```

3. From step 2, replace the second index of `state` with `object`

4. Fetch all the definitions into object like this:

```
{
    "title": <title>,
    "fixes_cve": <fixes_cve>,
    "severity": <severity>,
    "affected_cpe": <affected_cpe>
}
```

5. For each definition, assign the criteria
    1. Set the operation `or` or `and` recursively with the children elements
    2. Set the `criterion` inside criteria with the `state` field from the step 2 & 3