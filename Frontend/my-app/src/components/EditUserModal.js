// frontend/src/components/EditUserModal.js
import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { updateUser } from '../redux/slices/userSlice';

const EditUserModal = ({ user, onClose }) => {
  const dispatch = useDispatch();
  const [formData, setFormData] = useState({
    name: user.name,
    email: user.email,
    password: '',
  });

  const { name, email, password } = formData;

  const onChange = e => setFormData({ ...formData, [e.target.name]: e.target.value });

  const onSubmit = e => {
    e.preventDefault();
    const updatedData = { name, email };
    if (password) updatedData.password = password;
    dispatch(updateUser({ id: user._id, userData: updatedData }));
    onClose();
  };

  return (
    <div style={{
      position: 'fixed', top: 0, left:0, width:'100%', height:'100%', backgroundColor:'rgba(0,0,0,0.5)'
    }}>
      <div style={{
        position: 'relative', width: '300px', margin: '100px auto', padding: '20px', background: '#fff'
      }}>
        <h3>Edit User</h3>
        <form onSubmit={onSubmit}>
          <div>
            <label>Name:</label>
            <input type="text" name="name" value={name} onChange={onChange} required />
          </div>
          <div>
            <label>Email:</label>
            <input type="email" name="email" value={email} onChange={onChange} required />
          </div>
          <div>
            <label>Password:</label>
            <input type="password" name="password" value={password} onChange={onChange} placeholder="Leave blank to keep unchanged" />
          </div>
          <button type="submit">Update</button>
          <button type="button" onClick={onClose} style={{marginLeft: '10px'}}>Cancel</button>
        </form>
      </div>
    </div>
  );
};

export default EditUserModal;
