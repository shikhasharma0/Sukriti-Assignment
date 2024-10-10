
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import axios from 'axios';

const initialState = {
  users: [],
  loading: false,
  error: null,
};

// Fetch Users
export const fetchUsers = createAsyncThunk(
  'users/fetchUsers',
  async (_, { getState, rejectWithValue }) => {
    const token = getState().auth.token;
    try {
      const res = await axios.get('http://localhost:5000/api/users', {
        headers: { Authorization: token },
      });
      return res.data;
    } catch (err) {
      return rejectWithValue(err.response.data.message);
    }
  }
);

// Update User
export const updateUser = createAsyncThunk(
  'users/updateUser',
  async ({ id, userData }, { getState, rejectWithValue }) => {
    const token = getState().auth.token;
    try {
      const res = await axios.put(`http://localhost:5000/api/users/${id}`, userData, {
        headers: { Authorization: token },
      });
      return res.data;
    } catch (err) {
      return rejectWithValue(err.response.data.message);
    }
  }
);

// Delete User
export const deleteUser = createAsyncThunk(
  'users/deleteUser',
  async (id, { getState, rejectWithValue }) => {
    const token = getState().auth.token;
    try {
      await axios.delete(`http://localhost:5000/api/users/${id}`, {
        headers: { Authorization: token },
      });
      return id;
    } catch (err) {
      return rejectWithValue(err.response.data.message);
    }
  }
);

const userSlice = createSlice({
  name: 'users',
  initialState,
  reducers: {},
  extraReducers: {
    [fetchUsers.pending]: (state) => {
      state.loading = true;
      state.error = null;
    },
    [fetchUsers.fulfilled]: (state, action) => {
      state.loading = false;
      state.users = action.payload;
    },
    [fetchUsers.rejected]: (state, action) => {
      state.loading = false;
      state.error = action.payload;
    },
    [updateUser.fulfilled]: (state, action) => {
      const index = state.users.findIndex(user => user._id === action.payload._id);
      if (index !== -1) {
        state.users[index] = action.payload;
      }
    },
    [deleteUser.fulfilled]: (state, action) => {
      state.users = state.users.filter(user => user._id !== action.payload);
    },
  },
});

export default userSlice.reducer;
