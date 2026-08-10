import { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Alert,
} from "@mui/material";
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
} from "@mui/icons-material";
import { usersApi, type UserResponse } from "../../api/client";

export default function Users() {
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<UserResponse | null>(null);
  const [form, setForm] = useState({ username: "", password: "", role: "user", full_name: "" });
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const { data } = await usersApi.list();
      setUsers(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    setError("");
    try {
      await usersApi.create(form);
      setDialog(null);
      setForm({ username: "", password: "", role: "user", full_name: "" });
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleEdit = async () => {
    if (!editing) return;
    setError("");
    try {
      await usersApi.update(editing.id, {
        full_name: form.full_name || undefined,
        password: form.password || undefined,
        role: form.role || undefined,
      });
      setDialog(null);
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  const handleDelete = async () => {
    if (!editing) return;
    try {
      await usersApi.delete(editing.id);
      setDialog(null);
      setEditing(null);
      load();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка");
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Пользователи</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => { setForm({ username: "", password: "", role: "user", full_name: "" }); setDialog("create"); }}
        >
          Создать
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Имя пользователя</TableCell>
              <TableCell>Полное имя</TableCell>
              <TableCell>Роль</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell>Создан</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((u) => (
              <TableRow key={u.id} hover>
                <TableCell>{u.id}</TableCell>
                <TableCell>{u.username}</TableCell>
                <TableCell>{u.full_name || "—"}</TableCell>
                <TableCell>
                  <Chip
                    label={u.role === "admin" ? "Администратор" : "Пользователь"}
                    color={u.role === "admin" ? "error" : "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={u.is_active ? "Активен" : "Отключён"}
                    color={u.is_active ? "success" : "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>{new Date(u.created_at).toLocaleDateString("ru-RU")}</TableCell>
                <TableCell align="center">
                  <IconButton size="small" onClick={() => {
                    setEditing(u);
                    setForm({ username: u.username, password: "", role: u.role, full_name: u.full_name });
                    setDialog("edit");
                  }}>
                    <EditIcon fontSize="small" />
                  </IconButton>
                  <IconButton size="small" onClick={() => { setEditing(u); setDialog("delete"); }}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Новый пользователь</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Имя пользователя" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Полное имя" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} sx={{ mb: 2 }} />
          <TextField fullWidth label="Пароль" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} sx={{ mb: 2 }} />
          <FormControl fullWidth>
            <InputLabel>Роль</InputLabel>
            <Select value={form.role} label="Роль" onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <MenuItem value="user">Пользователь</MenuItem>
              <MenuItem value="admin">Администратор</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleCreate}>Создать</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "edit"} onClose={() => setDialog(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Редактировать: {editing?.username}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Полное имя" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} sx={{ mt: 1, mb: 2 }} />
          <TextField fullWidth label="Новый пароль (пусто = без изменений)" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} sx={{ mb: 2 }} />
          <FormControl fullWidth>
            <InputLabel>Роль</InputLabel>
            <Select value={form.role} label="Роль" onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <MenuItem value="user">Пользователь</MenuItem>
              <MenuItem value="admin">Администратор</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button variant="contained" onClick={handleEdit}>Сохранить</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить пользователя?</DialogTitle>
        <DialogContent>
          <Typography>Пользователь «{editing?.username}» будет удалён.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
