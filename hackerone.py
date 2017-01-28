import json
import io
from datetime import datetime

epoch = datetime(1970, 1, 1)


def epoch_seconds(date):
    """ This function converts the time to time since epoch time. It allows
        us to use time in our trending analysis, if needed.
    """
    date = date[:-6]
    date = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
    timedelta = date - epoch
    return timedelta


def open_vulnerabilities(vulnerability_file):
    """This function opens the vulnerabilities file and returns the
       vulnerabilities which haven't been resolved yet.
    """
    with open(vulnerability_file) as json_data:
        vulnerability_data = json.load(json_data)
    vulnerabilities_to_look_at = []
    for vulnerability_dict in vulnerability_data:
        if not vulnerability_dict["state"]:
            time_stamped = epoch_seconds(vulnerability_dict["created_at"])
            vulnerabilities_to_look_at.append(
                (vulnerability_dict["id"], time_stamped))
    return vulnerabilities_to_look_at


def data_on_open_vulnerabilities(actions, file):
    """This function takes in the open vulnerabilities and saves the upvotes,
       downvotes, time the action was entered and who entered the action"""
    with open(file) as json_data:
        actions_data = json.load(json_data)
    hacker_id_dict_compiled = {}
    vulnerabilities_to_look_at = []
    for item in actions:
        vulnerabilities_to_look_at.append(item[0])
    for hacker_id_dict in actions_data:
        vulnerability_id = hacker_id_dict["vulnerability_id"]
        if vulnerability_id in vulnerabilities_to_look_at:
            time_stamped = epoch_seconds(hacker_id_dict["created_at"])
            created_by = hacker_id_dict["created_by"]
            if hacker_id_dict["type"] == "downvote":
                upvote = 0
                downvote = 1
            elif hacker_id_dict["type"] == "upvote":
                upvote = 1
                downvote = 0
            hacker_id_dict[vulnerability_id] = (
                time_stamped, created_by, upvote, downvote)
            if vulnerability_id in hacker_id_dict_compiled.keys():
                hacker_id_dict_compiled[vulnerability_id].append(
                    hacker_id_dict[vulnerability_id])
            else:
                hacker_id_dict_compiled[vulnerability_id] = [
                    hacker_id_dict[vulnerability_id]]
    return hacker_id_dict_compiled


def up_down(open_vulerabilities):
    """ This function tabulates the number of upvotes and downvotes for
        every open vulnerability
    """
    dict_vulnerabilities = {}
    for key in open_vulerabilities:
        upvote_total = 0
        downvote_total = 0
        vulnerability_analyzed = open_vulerabilities[key]

        num_of_vulnerabilities = len(vulnerability_analyzed)

        for item in vulnerability_analyzed:
            if item[2] == 1:
                upvote_total += 1
            if item[3] == 1:
                downvote_total += 1
        dict_vulnerabilities[key] = (num_of_vulnerabilities, upvote_total, downvote_total,
                                     upvote_total - downvote_total, float(upvote_total) / downvote_total)
    return dict_vulnerabilities


def prioritize(up_down, priority_list=None, count=None):
    """ This function prioritizes which vulnerabilites are the most 
        important to fix. I only looked at vulnerabilities with a 
        minimum of more than 250 actions on them...
        from the list of vulnerabilities with more than 250 actions,
        I printed them in order of largest number of upvotes - downvotes
    """
    if count is None:
        count = 0
    if priority_list is None:
        priority_list = []
        for key in up_down:
            if up_down[key][0] > 250:
                priority_list.append((key, up_down[key]))
    count = 0
    print priority_list, priority_list[0][1][3]
    for i in range(len(priority_list) - 1):
        if priority_list[i][1][3] < priority_list[i + 1][1][3]:
            count += 1
            temp = priority_list[i]
            priority_list[i] = priority_list[i + 1]
            priority_list[i + 1] = temp
    if count == 0:
        return priority_list
    else:
        prioritize(up_down, priority_list, count)
        return priority_list


def display_results(priorities):
    """ This function is purely to list the results."""
    print "Here are our priorities in order of vulnerability id number"
    vulnerabilities_in_order = []
    i = 1
    for item in priorities:
        if i < 10:
            if len(str(item[0])) == 4:
                vulnerabilities_in_order.append(str(i) + ".".ljust(3) + str(item[0]))
            else:
                vulnerabilities_in_order.append(str(i) + ".".ljust(4) + str(item[0]))
        else:
            if len(str(item[0])) == 4:
                vulnerabilities_in_order.append(str(i) + ". ".ljust(2) + str(item[0]))
            else:
                vulnerabilities_in_order.append(str(i) + ". ".ljust(3) + str(item[0]))
        i += 1
    return vulnerabilities_in_order

def json_priorities(priorities, all_vulnerabilities, vulnerability_file):
    with open(vulnerability_file) as json_data:
        vulnerability_data = json.load(json_data)
    priority_add = []
    for item in priorities:
        print item
        for vulnerability_dict in vulnerability_data:
            if vulnerability_dict["id"] == item[0]:
                priority_add.append(vulnerability_dict)
    with io.open('priorities_in.json','wb') as outfile:
        json.dump(priority_add,outfile)
        
        
       
    #     vulnerability_list.append(all_vulnerabilities[item[0]])
    # print vulnerability_list
    # with open(json_priorities.json,'wb') as outfile:
    #     json.dump(row,json_priorities.json)



if __name__ == "__main__":
    all_vulnerabilities = open_vulnerabilities('vulnerabilities.json')
    data_on_open_vulnerabilities = data_on_open_vulnerabilities(
        all_vulnerabilities, 'actions.json')
    up_down = up_down(data_on_open_vulnerabilities)
    priorities = prioritize(up_down)
    display = display_results(priorities)
    json_priorities = json_priorities(priorities, all_vulnerabilities, 'vulnerabilities.json')


# Reddit Algorithm
# def score(ups, downs):
#     return ups - downs

# def hot(ups, downs, date):
#     s = score(ups, downs)
#     order = log(max(abs(s), 1), 10)
#     sign = 1 if s > 0 else -1 if s < 0 else 0
#     seconds = epoch_seconds(date) - 1134028003
#     return round(sign * order + seconds / 45000, 7)
