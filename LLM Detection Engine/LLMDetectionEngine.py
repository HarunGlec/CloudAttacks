import json
import time
import csv
from openai import OpenAI, RateLimitError
from pydantic import BaseModel


# Define the output model
class DetectionOutput(BaseModel):
    malicious: bool
    detection_name: str
    event_time: str
    title: str
    description: str
    remediation_actions: str

# Function to detect malicious activity
def detect_malicious_activity(client, rule, event, history):
    history.append({ "role": "user", "content": f"{event}" })
    try:
        print("Asking to GPT..")
        response = client.responses.parse(
            model="gpt-4.1-mini-2025-04-14",
            input=history,
            instructions=f"""You will analyze cloud logs to detect malicious activities according to given rule.
Tell me if the activity is malicious. 
If it is malicious, give me detection name based on rule, event time, alert title, description, and remediation actions. 
Provide 'malicious' variable as boolean in the output. 
If activity is not malicious, return 'malicious' variable as false, event time as activity time, title variable as title of event and description as explanation. 
Those non-malicious events can be associated with other malicious activities. To decide maliciousness of current event consider history.
Analyze events with given detection conditions in order. Detections written in priority order. You need to check first detection first.
Rule:
{rule}""",
            temperature=0.5,
            text_format=DetectionOutput,
            #previous_response_id=previous_id,
        )
        return response
    except RateLimitError:
        print("Rate limit exceeded. Retrying in 10 seconds...")
        time.sleep(10)
        return detect_malicious_activity(client, rule, event, history)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def load_events_and_rule(event_file, rule_file):
    # Load events
    with open(event_file, 'r') as file:
        if event_file.endswith('.json'):
            events = json.load(file)['Records']
        else:
            events = file.readlines()

    # Load rule
    with open(rule_file, 'r') as file:
        rule = file.read()

    return events, rule

def analyze(client, rule, events):
    # Prepare lists for malicious and non-malicious events
    malicious_events = []
    non_malicious_events = []
    history = []

    # Analyze events
    for idx, event in enumerate(events):
        if len(history) == 100 :
            history = []
        print(f"Processing event {idx+1}/{len(events)}...")
        response = detect_malicious_activity(client, rule, event, history)
        if response:
            result = response.output_parsed
            event_data = {
                "event_index": idx,
                "malicious": result.malicious,
                "detection": result.detection_name,
                "event_time": result.event_time,
                "title": result.title,
                "description": result.description,
                "remediation_actions": result.remediation_actions
            }
            if result.malicious:
                with open('malicious_events.csv', 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow(event_data.values())
                    file.close()
                #malicious_events.append(event_data)
                history = []
            else:
                with open('non_malicious_events.csv', 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow(event_data.values())
                    file.close()
                #non_malicious_events.append(event_data)
                history.append({"role":"assistant", "content":f"event_time:{event_data['event_time']} title:{event_data['title']} description:{event_data['description']}"})

    #write_results(malicious_events, non_malicious_events)

def write_results(malicious_events, non_malicious_events):
    # Write malicious events to CSV
    print("Malicious events have been writing..")
    with open('malicious_events.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["event_index", "malicious", "detection", "event_time", "title", "description", "remediation_actions"])
        writer.writeheader()
        writer.writerows(malicious_events)

    # Write non-malicious events to CSV
    print("Non-Malicious events have been writing..")
    with open('non_malicious_events.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["event_index", "malicious", "detection", "event_time", "title", "description", "remediation_actions"])
        writer.writeheader()
        writer.writerows(non_malicious_events)

    print("CSV files created successfully!")


if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else None
    rule_file = sys.argv[2] if len(sys.argv) > 2 else None
    if not log_file or not rule_file:
        print('Usage: LLMDetectionEngine.py <log_file_path> <rule_file_path>')
        sys.exit()


    # Initialize OpenAI client
    client = OpenAI()

    print("Malicious events file have been creating..")
    with open('malicious_events.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["event_index", "malicious", "detection", "event_time", "title", "description", "remediation_actions"])
        writer.writeheader()

    print("Non-Malicious events file have been creating..")
    with open('non_malicious_events.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["event_index", "malicious", "detection", "event_time", "title", "description", "remediation_actions"])
        writer.writeheader()
       

    events, rule = load_events_and_rule(log_file, rule_file)
    analyze(client, rule, events)
    print("All events analyzed. Stopping..")



