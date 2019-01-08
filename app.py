import requests
import xml.etree.ElementTree as ET
import json

URL_REDHAT_VULNERABILITIES = "http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml"
NAMESPACE = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
NAMESPACE_RED_DEV = "{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}"

def parse_element(element, xpath, as_list = False):
    if as_list:
        lists = []
        for e in element.findall(xpath.format(NS=NAMESPACE)):
            lists.append(e.text)
        return lists
    else:
        return element.find(xpath.format(NS=NAMESPACE)).text

def parse_criteria(criteria, tests):
    if criteria.tag == '{}criteria'.format(NAMESPACE):
        if criteria.attrib['operator'] == 'OR':
            return {"or": [parse_criteria(child, tests) for child in criteria]}
        elif criteria.attrib['operator'] == 'AND':
            return {"and": [parse_criteria(child, tests) for child in criteria]}
    elif criteria.tag == '{}criterion'.format(NAMESPACE):
        # fill the object name
        test = tests[criteria.attrib['test_ref']]
        for state in test['state']:
            state[1] = test['object']
        
        return test['state']

def fetch_data_as_xml():
    data = ""

    # Read data from URL
    r = requests.get(URL_REDHAT_VULNERABILITIES)
    data = r.text

    # parse data into XML object
    root = ET.fromstring(data)

    # parse objects
    objects = {}
    object_xpath = "./{NS}objects/{NS_RED_DEV}rpminfo_object"
    for rpminfo_object in root.findall(object_xpath.format(NS=NAMESPACE, NS_RED_DEV=NAMESPACE_RED_DEV)):
        id_ = rpminfo_object.attrib['id']
        name_ = rpminfo_object.find("./{}name".format(NAMESPACE_RED_DEV)).text
        objects[id_] = name_

    # parse states
    states = {}
    state_xpath = "./{NS}states/{NS_RED_DEV}rpminfo_state"
    for rpminfo_state in root.findall(state_xpath.format(NS=NAMESPACE, NS_RED_DEV=NAMESPACE_RED_DEV)):
        id_ = rpminfo_state.attrib['id']
        states[id_] = []

        # parse evr
        try:
            evr_ = rpminfo_state.find("./{}evr".format(NAMESPACE_RED_DEV))
            states[id_].append([
                "evr", "", evr_.attrib['operation'], evr_.text
            ])
        except:
            pass
        
        # parse arch
        try:
            arch_ = rpminfo_state.find("./{}arch".format(NAMESPACE_RED_DEV))
            states[id_].append([
                "arhc", "", arch_.attrib['operation'], arch_.text
            ])
        except:
            pass

        # parse signature_keyid
        try:
            signature_keyid_ = rpminfo_state.find(
                "./{}signature_keyid".format(NAMESPACE_RED_DEV))
            states[id_].append([
                "signature_keyid", "", signature_keyid_.attrib['operation'], signature_keyid_.text
            ])
        except:
            pass

        # parse version
        try:
            version_ = rpminfo_state.find(
                "./{}version".format(NAMESPACE_RED_DEV))
            states[id_].append([
                "version", "", version_.attrib['operation'], version_.text
            ])
        except:
            pass

    # parse tests
    tests = {}
    test_xpath = "./{NS}tests/{NS_RED_DEV}rpminfo_test"
    for rpminfo_state in root.findall(test_xpath.format(NS=NAMESPACE, NS_RED_DEV=NAMESPACE_RED_DEV)):
        check_ = rpminfo_state.attrib['check'] if 'check' in rpminfo_state.attrib else ''
        comment_ = rpminfo_state.attrib['comment'] if 'comment' in rpminfo_state.attrib else ''
        id_ = rpminfo_state.attrib['id'] if 'id' in rpminfo_state.attrib else ''

        object_ = rpminfo_state.find("./{}object".format(NAMESPACE_RED_DEV))
        state_ = rpminfo_state.find("./{}state".format(NAMESPACE_RED_DEV))

        tests[id_] = {
            "check": check_,
            "comment": comment_,
            "object": objects[object_.attrib['object_ref']],
            "state": states[state_.attrib['state_ref']]
        }
    
    # parse definition advesories
    data = []
    definition_xpath = "./{NS}definitions/{NS}definition"
    for definition in root.findall(definition_xpath.format(NS=NAMESPACE)):
        
        id_ = definition.attrib['id']

        title_xpath = "./{NS}metadata/{NS}title"
        fixes_cve_xpath = "./{NS}metadata/{NS}advisory/{NS}cve"
        severity_xpath = "./{NS}metadata/{NS}advisory/{NS}severity"
        affected_cpe_xpath = "./{NS}metadata/{NS}advisory/{NS}affected_cpe_list/{NS}cpe"
        criteria_xpath = "./{NS}criteria"

        # parse data
        record = {
            "title": parse_element(definition, title_xpath),
            "fixes_cve": parse_element(definition, fixes_cve_xpath, True),
            "severity": parse_element(definition, severity_xpath),
            "affected_cpe": parse_element(definition, affected_cpe_xpath, True)
        }

        # parse criteria
        criteria_element = definition.find(criteria_xpath.format(NS=NAMESPACE))
        record['criteria'] = parse_criteria(criteria_element, tests)

        data.append(record)

    # save json into file
    with open("com.redhat.rhsa-all.json", 'w') as file:
        json.dump({
            "advisory": data
        }, file)

fetch_data_as_xml()
