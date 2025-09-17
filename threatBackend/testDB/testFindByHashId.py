from threat_process import utils_db

hash_id="1234"
print(utils_db.findCommitJSONbyHashID(hash_id))
print(utils_db.findDFDJSONbyHashID(hash_id))
print(utils_db.findDreadJSONbyHashID(hash_id))
print(utils_db.findThreatModelsJSONbyHashID(hash_id))
