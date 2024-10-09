from flask import Flask, request, jsonify
import joblib
import warnings

xss_bad_words = [
    "<script>",
    "javascript:",
    "onload",
    "onerror",
    "<img>",
    "<iframe>",
    "<body>",
    "alert()",
    "document.cookie",
    '<a href="javascript:',
    "eval()",
    "<svg>",
    "<style>",
    "<meta>",
    "onfocus",
    "onmouseover",
    "innerHTML",
    "XMLHttpRequest",
    "<input>",
    "src",
    "window.location",
    "parent.location",
    "top.location",
    "setTimeout()",
    "setInterval()",
    "<form>",
    "<object>",
    "<embed>",
    "<video>",
    "<audio>",
    "<marquee>",
    "<table background=",
    "<link>",
     "select", 
    "delete", 
    "update", 
    "insert", 
    "drop", 
    "alter", 
    "create", 
    "truncate", 
    "union", 
    "group by", 
    "order by", 
    "having", 
    "exec", 
    "execute", 
    "declare", 
    "cast", 
    "convert", 
    "use", 
    "shutdown", 
    "xp_cmdshell", 
    "sp_executesql", 
    "information_schema", 
    "sysobjects", 
    "syscolumns", 
    "sysdatabases", 
    "sysusers"
    ]

def count_words(line):
        count = 0
        for word in xss_bad_words:
            count += line.count(word)
        return count

def preprocessing(data):
    l1 = data.strip()
    single_quote = l1.count("'")
    double_quote = l1.count("\"")
    badwords = count_words(data)
    round_braces = l1.count("(") + l1.count(")")
    angular_brackets = l1.count("<") + l1.count(">")
    forward_slash = l1.count('/')
    dash = l1.count('-')
    hash = l1.count('#')
    astrict = l1.count('*')
    ampercent = l1.count('&')
    equalto = l1.count('=')
    return [single_quote, double_quote, dash, hash, astrict, ampercent, equalto, badwords, round_braces, angular_brackets, forward_slash]

app = Flask(__name__)

model = joblib.load('random_forest_model.joblib')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if('payload' in data):
        warnings.filterwarnings("ignore", message="X does not have valid feature names")
        processed_data = preprocessing(data['payload'])
        prediction = model.predict([processed_data])
        if prediction[0] == 0:
             return jsonify({"error": "false",
                    "message": "Intrusion not detected"
                    })
        else:
             print("Intrusion detected")
             return jsonify({"error": "false",
                    "message": "Intrusion Detected"
                    })
    else:
        return jsonify({
            "error": "true",
            "message": "The body should contain a payload."
        })

if __name__ == '__main__':
    app.run(debug=True)
