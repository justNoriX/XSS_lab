from flask import Flask, request, redirect
import html

app = Flask(__name__)

comments = []
current_security_level = "none"
current_filter= "none"


show_code_visible = False

code_snippets = {
    "none": "<div>{{ user_input }}</div>",
    "class_atr": "<div class=\"{{ user_input }}\">",
    "href_atr": "<a href=\"{{ user_input }}\">",
    "js_chain": "<script>\n  var msg = '{{ user_input }}';\n  console.log(msg);\n</script>",
    "template": "<script>\n  const info = `Użytkownik: {{ user_input }}`;\n  console.log(info);\n</script>"
}

def sanitize_input(text):

    if current_filter == "none":
        return text
    
    elif current_filter == "case_sensitive":
        # FILTR 1: Usuwa tylko <script> małymi literami
        return text.replace("<script>", "").replace("</script>", "")
    
    elif current_filter == "blacklist":
        # FILTR 2: Blacklista popularnych słów
        blacklist = ["alert", "script", "onerror", "onmouseover", "javascript"]
        temp_text = text
        for word in blacklist:
            # Usuwamy bez względu na wielkość liter
            import re
            insensitivity = re.compile(re.escape(word), re.IGNORECASE)
            temp_text = insensitivity.sub("[ZABLOKOWANE]", temp_text)
        return temp_text
        
    elif current_filter == "encoding":
        # FILTR 3: Zamiana < i > na encje HTML
        return text.replace("<", "&lt;").replace(">", "&gt;")
    
    return text

@app.route('/')
def index():
    levels = ["none", "class_atr", "href_atr", "js_chain", "template"]
    level_options = "".join([f'<option value="{l}" {"selected" if current_security_level == l else ""}>{l.upper()}</option>' for l in levels])

    filters = ["none", "case_sensitive", "blacklist", "encoding"]
    filter_options = "".join([f'<option value="{f}" {"selected" if current_filter == f else ""}>{f.upper()}</option>' for f in filters])

#    context_descriptions = {
#        "none": "CEL: Wstrzyknięcie prostego taga. Kontekst: &lt;div&gt;[XSS]&lt;/div&gt;",
#        "low": "CEL: Wypadnięcie z atrybutu. Kontekst: &lt;div class=\"[XSS]\"&gt;",
#        "medium": "CEL: Atak przez protokół. Kontekst: &lt;a href=\"[XSS]\"&gt;",
#        "high": "CEL: Ucieczka z łańcucha JS. Kontekst: &lt;script&gt; var msg = '[XSS]'; &lt;/script&gt;"
#    }

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Pentest Lab</title>
        <style>
            body {{ font-family: sans-serif; line-height: 1.6; margin: 20px; background: #f4f4f4; }}
            .container {{ max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .settings {{ background: #333; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .comment {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-left: 5px solid #007bff; background: #fff; }}
            .comment-info {{ font-size: 0.8em; color: #666; margin-bottom: 5px; border-bottom: 1px solid #eee; }}
            .code-preview {{ background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; font-family: monospace; margin-bottom: 20px; white-space: pre; }}
            button {{ cursor: pointer; padding: 8px 15px; border-radius: 4px; border: none; }}
            .btn-blue {{ background: #007bff; color: white; }}
            .btn-red {{ background: #dc3545; color: white; }}
            select {{ padding: 5px; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="settings">
                <form action="/set_security" method="POST">
                    <strong>Kontekst: </strong>
                    <select name="level">{level_options}</select>
                    &nbsp;&nbsp;
                    <strong>Filtr: </strong>
                    <select name="filter">{filter_options}</select>
                    <button type="submit" class="btn-blue">Zastosuj</button>
                </form>
                <hr style="opacity:0.3">
                <form action="/show_code" method="POST" style="display:inline;">
                    <button type="submit" style="background:#6c757d; color:white;">
                        {'Ukryj kod' if show_code_visible else 'Pokaż kod źródłowy'}
                    </button>
                </form>
                <form action="/clear_comments" method="POST" style="display:inline; float:right;">
                    <button type="submit" class="btn-red">Wyczyść wszystko</button>
                </form>
            </div>

            <div class="context-box" style="background: #fff3cd; padding: 10px; border: 1px solid #ffeeba; margin-bottom: 10px; font-family: monospace;">
                <strong>AKTYWNY FILTR:</strong> {current_filter.upper()}
            </div>

            {f'<div class="code-preview"><strong>Server-side:</strong><br>{html.escape(code_snippets.get(current_security_level, ""))}</div>' if show_code_visible else ''}

            <form action="/add_comment" method="POST">
                <input type="text" name="author" placeholder="Twoje imię" style="width:100%; padding:8px; margin-bottom:10px;">
                <textarea name="comment" placeholder="Twój payload" style="width:100%; height:80px; padding:8px;"></textarea>
                <button type="submit" class="btn-blue" style="width:100%">Wyślij</button>
            </form>

            <hr>
            <h3>Wynik renderowania:</h3>
            <h6>Made by NoriX</h6>
    """

#    if show_code_visible:

#        snippet = code_snippets.get(current_security_level, "")
#        html_content += f"""
#        <div class="code-preview">
#<strong>Kontekst renderowania (Server-side):</strong>
#{html.escape(snippet)}
#        </div>
#        """

    for c in comments:
        # Renderujemy komentarz w zależności od poziomu
        if c['level'] == "none":
            # Kontekst: Zwykły tekst wewnątrz DIV
            html_content += f"<div class='comment'><strong>{c['author']}:</strong> <div>{c['text']}</div></div>"
        
        elif c['level'] == "class_atr":
            # Kontekst: Atrybut klasy
            html_content += f"""
                <div class='comment'>
                    <strong>{c['author']}:</strong> 
                    <div class="{c['text']}">
                        Treść: {c['text']} 
                    </div>
                </div>
            """            
        elif c['level'] == "href_atr":
            # Kontekst: Atrybut href
            html_content += f"""
                <div class='comment'>
                    <strong>{c['author']}:</strong> 
                    <a href="{c['text']}">
                        Treść: {c['text']} 
                    </a>
                </div>
            """
            
        elif c['level'] == "js_chain":
            # Kontekst: Wewnątrz bloku skryptu (wymaga ucieczki z ' ')
            html_content += f"""
                <div class='comment'>
                    <strong>{c['author']}:</strong>
                    <script>
                        var userMsg = '{c['text']}';
                        console.log('Log: ' + userMsg);
                    </script>
                </div>
            """
        elif c['level'] == "template":
            # Kontekst: JavaScript Template Literal
            html_content += f"""
                <div class='comment'>
                    <div class='comment-meta'>Autor: {c['author']} | Kontekst: {c['level']}</div>
                    <script>
                        const info = `Użytkownik: {c['text']}`;
                        console.log(info);
                    </script>
                </div>
            """

    html_content += "</div></body></html>"
    return html_content

@app.route('/set_security', methods=['POST'])
def set_security():
    global current_security_level, current_filter
    current_security_level = request.form.get('level', 'none')
    current_filter = request.form.get('filter', 'none')
    return redirect('/')

@app.route('/add_comment', methods=['POST'])
def add_comment():
    author = request.form.get('author', 'Anon')
    text = request.form.get('comment', '')
    safe_text = sanitize_input(text)
    comments.append({'author': author, 'text': safe_text, 'level': current_security_level, 'filter': current_filter})
    return redirect('/')

@app.route('/clear_comments', methods=['POST'])
def clear_comments():
    global comments
    comments = []
    return redirect('/')

@app.route('/show_code', methods=['POST'])
def show_code():
    global show_code_visible
    show_code_visible = not show_code_visible
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
