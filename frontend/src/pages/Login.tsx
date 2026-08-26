import { useState } from "react";
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
  CircularProgress,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import LoginIcon from "@mui/icons-material/Login";
import { useAuthStore } from "../store/auth";

export default function Login() {
  const { login } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка входа");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <Paper elevation={3} sx={{ p: 4, width: "100%", maxWidth: 400 }}>
          <Box sx={{ display: "flex", justifyContent: "center", mb: 2 }}>
            <SecurityIcon sx={{ fontSize: 48, color: "primary.main" }} />
          </Box>
          <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 3 }}>
            Вход в систему
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Имя пользователя"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              margin="normal"
              required
              autoFocus
            />
            <TextField
              fullWidth
              label="Пароль"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              margin="normal"
              required
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              disabled={loading}
            >
              {loading ? <CircularProgress size={24} /> : "Войти"}
            </Button>
          </Box>

          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Первичная настройка:</strong> при первом запуске пароль администратора
              выводится в журнал systemd (<code>journalctl -u fstec-backend</code>)
              и в файл <code>backend.log</code>. Имя пользователя: <strong>admin</strong>.
            </Typography>
          </Alert>
        </Paper>
      </Box>
    </Container>
  );
}
