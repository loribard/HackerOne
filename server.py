from flask import Flask, render_template
from hackerone import open_vulnerabilities, data_on_open_vulnerabilities, up_down, prioritize, display_results
   

app = Flask(__name__)
app.secret_key = "ABC"


@app.route('/')
def homepage():
    print "got here"
    actions = open_vulnerabilities('vulnerabilities.json')
    vulnerabilities = data_on_open_vulnerabilities(actions, 'actions.json')
    up_down_analysis = up_down(vulnerabilities)
    prioritized = prioritize(up_down_analysis)
    priorities = display_results(prioritized)
    return render_template("homepage.html", priorities=priorities)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
