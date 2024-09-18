# socket_server.py
from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room
import logging

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    logging.info(f"New client connected: {request.sid}")
    emit('status', {'msg': 'Connected to the socket server.'})

@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{username} has entered the room.'}, room=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    emit('message', data, room=room)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{username} has left the room.'}, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5001)  # Use a different port