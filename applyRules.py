from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import json
import uvicorn
from contextlib import asynccontextmanager

active_rules = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    '''Load all rules in memory on startup'''
    # Run at startup
    fetch_all_rules()
    yield

app = FastAPI(lifespan=lifespan)
RULES_FILE = 'rules.json'

def fetch_rules_from_file():
    global active_rules
    with open(RULES_FILE, 'r') as f:
        result = json.load(f)
        active_rules = result
        return result

@app.middleware('http')
async def reload_rules(request, call_next):
    '''Added a custom middleware.On each POST call reload the rules in memory'''
    response = await call_next(request)
    if request.method == 'POST':
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
    return fetch_all_rules()

@app.get("/api/v1/rules/{rule_name}")
async def get_rule(rule_name: str):
    for rule in active_rules['rules']:
        if rule['name'] == rule_name:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8000)