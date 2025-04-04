import openai 
import json
import os
import math
import pandas as pd
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class ObjectType:
    """Represents an object type in the OCPM model"""
    name: str
    activities: List[str]
    attributes: List[str]
    relationships: List[str]


def chunk_dataframe(df, chunk_size=1000):
    """Split dataframe into chunks of specified size"""
    num_chunks = math.ceil(len(df) / chunk_size)
    return [df[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunks)]


def merge_object_types(object_types_list):
    """Merge object types from multiple chunks"""
    merged = {}
    for obj_types in object_types_list:
        for obj_name, obj_data in obj_types.items():
            if obj_name not in merged:
                merged[obj_name] = {
                    'name': obj_data['name'],
                    'activities': set(obj_data['activities']),
                    'attributes': set(obj_data['attributes']),
                    'relationships': set(obj_data['relationships'])
                }
            else:
                merged[obj_name]['activities'].update(obj_data['activities'])
                merged[obj_name]['attributes'].update(obj_data['attributes'])
                merged[obj_name]['relationships'].update(obj_data['relationships'])
    
    # Convert sets back to lists for JSON serialization
    for obj_name in merged:
        merged[obj_name]['activities'] = list(merged[obj_name]['activities'])
        merged[obj_name]['attributes'] = list(merged[obj_name]['attributes'])
        merged[obj_name]['relationships'] = list(merged[obj_name]['relationships'])
    
    return merged


def process_log_file(df: pd.DataFrame, chunk_size=100):
    try:
        # Set OpenAI API Key
        client = openai.OpenAI(api_key=os.getenv("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"))

        # Split into chunks
        chunks = chunk_dataframe(df, chunk_size)
        all_object_types = []

        for i, chunk in enumerate(chunks):
            print(f"Processing chunk {i+1}/{len(chunks)}")
            
            # Convert chunk to JSON string
            log_text = chunk.to_json(orient='records')
        
            prompt = f"""Convert the uploaded file into OCEL 1.0 JSON format while ensuring that:

            {log_text}

            ✅ The events contain unique IDs, timestamps, activities, attributes, and related objects.
            ✅ The objects store activity-related details and key business attributes.
            ✅ The output format follows the OCEL 1.0 JSON structure.
            
            Requirements:
            - Extract relevant entity types from the dataset
            - Format timestamps in ISO 8601
            - Link each event with its objects
            - Include attributes like case_id, resource, and object_type
            
            Follow this structure:
            {{
                "ocel:version": "1.0",
                "ocel:ordering": "timestamp",
                "ocel:attribute-names": [],
                "ocel:events": [...],
                "ocel:objects": [...],
                "ocel:object-types": [...],
                "ocel:global-log": {{
                    "ocel:attribute-names": []
                }}
            }}

            An object-centric process mining (OCPM), the goal is to model processes where multiple interacting objects (e.g., orders, clients, products) participate in events. The key challenge is determining what qualifies as an "object" from an event log. Let’s break down the fundamentals:
            1. What Qualifies as an Object?
            An object represents a business entity with its own lifecycle and attributes. Objects are not just event attributes; they are first-class citizens with identity and interactions. To qualify as an object, an entity must:
            Participate in multiple events (e.g., a Trade spans multiple steps).
            Have a lifecycle (e.g., a CurrencyPair might be referenced in multiple trades).
            Interact with other objects (e.g., a Client interacts with a Trade).
            
            Return only the json output without any additional text.
    and i need only object types as output in this format "
    Example
    'Trade': ObjectType(
                    name='Trade',
                    activities=[
                        'Trade Initiated', 'Trade Executed', 'Trade Allocated',
                        'Trade Settled', 'Trade Canceled'  # Match synthetic data activities
                    ],
                    attributes=['currency_pair', 'notional_amount'],
                    relationships=['Market', 'Risk', 'Settlement']
                ),
                'Market': ObjectType(
                    name='Market',
                    activities=[
                        'Trade Executed', 'Quote Requested', 'Quote Provided'
                    ],
                    attributes=['currency_pair'],
                    relationships=['Trade']
                ),
                'Risk': ObjectType(
                    name='Risk',
                    activities=[
                        'Trade Allocated', 'Risk Assessment'
                    ],
                    attributes=['risk_score'],
                    relationships=['Trade', 'Settlement']
                ),
                'Settlement': ObjectType(
                    name='Settlement',
                    activities=[
                        'Trade Settled', 'Position Reconciliation'
                    ],
                    attributes=['settlement_amount'],
                    relationships=['Trade', 'Risk']
                )
            "
            """

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a process mining expert"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                max_tokens=4000
            )

            try:
                chunk_result = json.loads(response["choices"][0]["message"]["content"])
                all_object_types.append(chunk_result)
            except json.JSONDecodeError as e:
                return f"Error parsing response: {str(e)}"

        merged_json = merge_object_types(all_object_types)

        # Convert merged JSON to ObjectType instances
        object_types = {}
        for obj_name, obj_data in merged_json.items():
            object_types[obj_name] = ObjectType(
                name=obj_data['name'],
                activities=obj_data['activities'],
                attributes=obj_data['attributes'],
                relationships=obj_data['relationships']
            )
        
        # Save to JSON file
        json_output = {obj_name: obj_type.__dict__ for obj_name, obj_type in object_types.items()}
        
        output_path = 'ocel/output_ocel.json'
        with open(output_path, 'w') as f:
            json.dump(json_output, f, indent=2)
        
        print(f"Object types saved to {output_path}")
        return object_types
        
    except Exception as e:
        print(f"Error connecting to OpenAI: {str(e)}")


# Example usage:
# df = pd.read_csv("your_file.csv")
# process_log_file(df)
