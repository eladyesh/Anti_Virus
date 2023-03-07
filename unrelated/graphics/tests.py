from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# A list to hold our todo items
todo_list = []


# Route to handle the home page
@app.route('/')
def index():
    global todo_list
    return render_template('index.html', todos=todo_list)


# Route to handle adding a new todo item
@app.route('/add', methods=['POST'])
def add():
    global todo_list
    # Get the new todo item from the form
    new_todo = {
        'id': len(todo_list) + 1,
        'text': request.form['new-todo'],
        'done': False
    }
    # Add the new todo item to the list
    todo_list.append(new_todo)
    # Redirect back to the home page
    return redirect(url_for('index'))


# Route to handle deleting a todo item
@app.route('/delete/<int:todo_id>', methods=['POST'])
def delete(todo_id):
    global todo_list
    # Remove the todo item from the list
    todo_list = [todo for todo in todo_list if todo['id'] != todo_id]
    # Redirect back to the home page
    return redirect(url_for('index'))


# Route to handle marking a todo item as done
@app.route('/done/<int:todo_id>', methods=['POST'])
def done(todo_id):
    global todo_list
    # Mark the todo item as done
    for todo in todo_list:
        if todo['id'] == todo_id:
            todo['done'] = True
            break
    # Redirect back to the home page
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
