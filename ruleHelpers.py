from mysqldb import db

def run_query(query, values):
    try:
        return db.execute_query(query, values)
    except Exception as e:
        raise e

def create_query(predicate, all_criterias, all_actions):
    table = 'mailbox'
    all_queries = []
    action_queries = []
    criterion_queries = []
    all_values = []
    query_prefix = f'UPDATE {table} SET '
    for rule in all_actions:
        for action in rule:
            querystring, stringreplace = helper_fns[action](rule[action])
            action_queries.append(querystring)
            all_values.append(stringreplace)
    if len(all_actions) > 1:
        action_query = query_prefix + ','.join(action_queries)
    else:
        action_query = query_prefix + action_queries[0]
    all_queries.append(action_query)

    for criteria in all_criterias:
        querystring, stringreplace  = helper_fns[criteria](all_criterias[criteria], criteria)
        criterion_queries.append(querystring)
        all_values.append(stringreplace)
    if predicate == 'all':
        criterion_query = ' AND '.join(criterion_queries)
    elif predicate == 'any':
        criterion_query = ' OR '.join(criterion_queries)
    all_queries.append(criterion_query)
    final_query = ' WHERE '.join(all_queries)
    return (final_query, all_values)

def string_query(rule, field):
    for k, v in rule.items():
        if k == 'contains':
            return (f"{field} LIKE %s", '%' + v + '%')
        elif k == 'doesnot contains':
            return (f"{field} NOT LIKE %s", '%' + v + '%')
        elif k == 'equals':
            return (f"{field} = %s", v)

def date_recieved_query(date_query, field):
    '''Considering only day for now'''
    for k, v in date_query.items():
        if k == 'less than':
            return ("recieved_date < CURDATE() - INTERVAL %s DAY", v)
        elif k == 'greater than':
            return ("recieved_date > CURDATE() - INTERVAL %s DAY", v)

def from_query(from_rule, _):
    for k, v in from_rule.items():
        if k == 'contains':
            return ("`from` LIKE %s", '%' + v + '%')
        elif k == 'doesnot contains':
            return ("`from` NOT LIKE %s", '%' + v + '%')
        elif k == 'equals':
            return ("`from` = %s", v)

def change_folder_query(folder):
    return ("folder = %s", folder)

def read_status_query(read_action):
    if read_action == True:
        return ("read = %s", 'TRUE')
    else:
        return ("read = %s", 'FALSE')

helper_fns = {
    'from': from_query,
    'subject': string_query,
    'messageid': string_query,
    'date recieved': date_recieved_query,
    'move to': change_folder_query,
    'read': read_status_query
}