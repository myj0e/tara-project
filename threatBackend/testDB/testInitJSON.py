import threat_process.utils_db as udb
import json
'''
运行结果：

'''

hash_id="1234"
commit=\
{
    'title': 'Test DFD',
    'description': 'This is a test DFD commit',
    'nodes': [
        {
            'id': 'a25bbb4e-093f-4238-a620-31efdee452dc',
            'name': 'Worker Config',
            'description':'',
            'type': 'actor',
            'hasOpenThreats': True,
            'threats': [
                {
                    "title":"Accessing DB credentials",
                    "severity":"High",
                    "type":"Information disclosure",
                    "mitigation":"Encrypt the DB credentials in the configuration file.\n\nExpire and replace the DB credentials regularly.",
                    "status":"Open"
                }
            ]
        },
        {
            'id': '936557f9-22e2-4bac-bb70-0089c5c2fbe1',
            'name': 'Database',
            'description':'',
            'type': 'store',
            'hasOpenThreats': True,
            'threats': [
                {
                    "title":"Accessing DB credentials",
                    "severity":"High",
                    "type":"Information disclosure",
                    "mitigation":"Encrypt the DB credentials in the configuration file.\n\nExpire and replace the DB credentials regularly.",
                    "status":"Open"
                }
            ]
        }
    ],
    'edges': [
        {
            'id': 'c779a822-d4ec-4237-9191-fe7170b32956',
            'name': 'Put Message',
            'description':'',
            'source': '0d9909ea-1398-4898-be81-cf1c808324dc',
            'target': 'ec574fb4-87e7-494b-88dc-2a3c99172067',
            'isEncrypted': False,
            'isPublicNetwork': False,
            'hasOpenThreats': True,
            'protocol': '',
            'threats': [
                {
                    "title":"Accessing DB credentials",
                    "severity":"High",
                    "type":"Information disclosure",
                    "mitigation":"Encrypt the DB credentials in the configuration file.\n\nExpire and replace the DB credentials regularly.",
                    "status":"Open"
                }
            ]
        }
    ]
}
udb.putDFDJSON2db(hash_id,commit)
commit_json = udb.getDFDJSON(hash_id)
print(commit_json)
print(json.loads(json.dumps(commit_json))==json.loads(json.dumps(commit)))

