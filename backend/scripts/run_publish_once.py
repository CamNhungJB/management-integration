from services.rule_generator import publish_rules_to_mongo

if __name__ == "__main__":
    result = publish_rules_to_mongo()
    print("RESULT:", result)
