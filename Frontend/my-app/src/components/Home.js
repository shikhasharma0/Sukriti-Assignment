// frontend/src/components/Home.js
import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchUsers, deleteUser } from '../redux/slices/userSlice';
import { logout } from '../redux/slices/authSlice';
import EditUserModal from './EditUserModal';

const Home = () => {
  const dispatch = useDispatch();
  const { users, loading, error } = useSelector(state => state.users);
  const [editUser, setEditUser] = useState(null);

  useEffect(() => {
    dispatch(fetchUsers());
  }, [dispatch]);

  const handleDelete = (id) => {
    if (window.confirm('Are you sure to delete this user?')) {
      dispatch(deleteUser(id));
    }
  };

  const handleLogout = () => {
    dispatch(logout());
  };

  return (
    <div>
      <h2>Home Page</h2>
      <button onClick={handleLogout}>Logout</button>
      {loading && <p>Loading users...</p>}
      {error && <p style={{color:'red'}}>{error}</p>}
      <table border="1" cellPadding="10">
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map(user => (
            <tr key={user._id}>
              <td>{user.name}</td>
              <td>{user.email}</td>
              <td>
                <button onClick={() => setEditUser(user)}>Edit</button>
                <button onClick={() => handleDelete(user._id)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {editUser && <EditUserModal user={editUser} onClose={() => setEditUser(null)} />}
    </div>
  );
};

export default Home;
