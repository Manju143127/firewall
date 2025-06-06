from flask import Flask, render_template, request, redirect, url_for
from firewall_core import firewall_rules, start_sniffing, add_iptables_rule, remove_iptables_rule
import threading

app = Flask(__name__)

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

@app.route('/')
def index():
    return render_template('index.html', rules=firewall_rules)

@app.route('/add_rule', methods=['POST'])
def add_rule():
    rule_type = request.form['type']
    value = request.form['value']

    if rule_type in firewall_rules:
        if rule_type == 'block_port':
            value = int(value)
        if value not in firewall_rules[rule_type]:
            firewall_rules[rule_type].append(value)
            add_iptables_rule(rule_type, value)

    return redirect(url_for('index'))

@app.route('/remove_rule', methods=['POST'])
def remove_rule():
    rule_type = request.form['type']
    value = request.form['value']

    if rule_type == 'block_port':
        value = int(value)

    if rule_type in firewall_rules and value in firewall_rules[rule_type]:
        firewall_rules[rule_type].remove(value)
        remove_iptables_rule(rule_type, value)

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5009)
