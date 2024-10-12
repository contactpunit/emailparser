from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import json
import uvicorn
from contextlib import asynccontextmanager
from ruleHelpers import create_query, run_query

active_rules = []
RULES_FILE = 'rules.json'

@asynccontextmanager
async def lifespan(app: FastAPI):
    '''Load all rules in memory on startup'''
    # Run at startup
    fetch_all_rules()
    yield

app = FastAPI(lifespan=lifespan)

def fetch_rules_from_file():
    global active_rules
    with open(RULES_FILE, 'r') as f:
        result = json.load(f)
        active_rules = result['rules']
        return result

@app.middleware('http')
async def reload_rules(request, call_next):
    '''Added a custom middleware.
    This makes sure any new rule addition will be loaded to memory'''
    response = await call_next(request)
    if request.method == 'POST' and request.url.path == '/api/v1/rules/':
        fetch_rules_from_file()
    return response

def fetch_all_rules():
    '''If rules already loaded in memory, return them else read from file, load and return'''
    try:
        if active_rules:
            return active_rules
        else:
            return fetch_rules_from_file()
    except IOError as e:
        raise HTTPException(status_code=500, detail=f"Unable to fetch the rules. Error: {e}")

@app.get("/api/v1/rules")
async def get_rules():
    '''Get all rules'''
    return fetch_all_rules()

@app.get("/api/v1/rules/{rule_name}")
async def get_rule(rule_name: str):
    '''Get specific rule by rule name'''
    for rule in active_rules:
        if rule['name'] == rule_name:
            return rule
    raise HTTPException(status_code=404, detail=f"Rule {rule_name} not found")

@app.post("/api/v1/rules/")
async def create_rule(rule):
    '''Api to create new rule and add it to JSON file. Needs to be implemented later'''
    pass
    
@app.post("/api/v1/rules/{rule_name}")
async def run_rule(rule_name: str):
    '''Execute a mail rule'''
    for rule in active_rules:
        if rule['name'] == rule_name:
            criterions = rule['criterias']
            predicate = rule['predicate']
            actions = rule['actions']
            (query, values) = create_query(predicate, criterions, actions)
            result = run_query(query, tuple(values))
            return {'result': result}
    raise HTTPException(status_code=404, detail="Rule not found")

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8000)