import { useEffect, useState } from "react";
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
  CircularProgress,
  Divider,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import LoginIcon from "@mui/icons-material/Login";
import { useAuthStore } from "../store/auth";
import { authApi } from "../api/client";

export default function Login() {
  const { login, needsSetup } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [bootstrap, setBootstrap] = useState<{ username: string; password: string } | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [bootstrapLoading, setBootstrapLoading] = useState(false);

  const loadBootstrap = async () => {
    setBootstrapLoading(true);
    setError("");
    try {
      const { data } = await authApi.bootstrap();
      setBootstrap(data);
      setUsername(data.username);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Не удалось получить временный пароль");
    } finally {
      setBootstrapLoading(false);
    }
  };

  useEffect(() => {
    if (needsSetup) {
      loadBootstrap();
    }
  }, [needsSetup]);

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

  const handleCopy = async () => {
    if (!bootstrap) return;
    try {
      await navigator.clipboard.writeText(bootstrap.password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Не удалось скопировать пароль");
    }
  };

  if (needsSetup && !bootstrap) {
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
            {bootstrapLoading ? (
              <>
                <Typography variant="h6" align="center" gutterBottom>
                  Первичная инициализация системы
                </Typography>
                <Box sx={{ display: "flex", justifyContent: "center", my: 3 }}>
                  <CircularProgress />
                </Box>
                <Typography variant="body2" color="text.secondary" align="center">
                  Ожидание запуска сервера...
                </Typography>
              </>
            ) : (
              <>
                <Typography variant="h6" align="center" gutterBottom>
                  Сервер недоступен
                </Typography>
                {error && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                  </Alert>
                )}
                <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 3 }}>
                  Не удалось получить временный пароль.
                </Typography>
                <Button fullWidth variant="contained" onClick={loadBootstrap}>
                  Повторить
                </Button>
              </>
            )}
          </Paper>
        </Box>
      </Container>
    );
  }

  if (needsSetup && bootstrap && !showLogin) {
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
            <Typography variant="h5" align="center" gutterBottom>
              Первичная инициализация системы
            </Typography>
            <Typography variant="body2" color="text.secondary" align="center" sx={{ mb: 3 }}>
              Учётная запись администратора создана автоматически
            </Typography>

            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {error}
              </Alert>
            )}

            <Alert severity="warning" sx={{ mb: 3 }}>
              Пароль показывается <strong>один раз</strong> — запишите его. После первого входа
              восстановить его нельзя.
            </Alert>

            <Box
              sx={{
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2,
                p: 2,
                mb: 3,
              }}
            >
              <Typography variant="body2" color="text.secondary">
                Имя пользователя
              </Typography>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {bootstrap.username}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Пароль
              </Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Typography
                  variant="h6"
                  sx={{ fontFamily: "monospace", wordBreak: "break-all" }}
                >
                  {bootstrap.password}
                </Typography>
                <Button
                  size="small"
                  startIcon={<ContentCopyIcon />}
                  onClick={handleCopy}
                  disabled={copied}
                >
                  {copied ? "Скопировано" : "Скопировать"}
                </Button>
              </Box>
            </Box>

            <Button
              fullWidth
              variant="contained"
              size="large"
              startIcon={<LoginIcon />}
              onClick={() => setShowLogin(true)}
              sx={{ mt: 1, mb: 2 }}
            >
              Перейти ко входу
            </Button>

            <Divider sx={{ my: 2 }} />
            <Typography variant="caption" color="text.secondary" align="center" sx={{ display: "block" }}>
              Сразу после входа создайте дополнительные учётные записи в разделе «Пользователи».
            </Typography>
          </Paper>
        </Box>
      </Container>
    );
  }

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
        </Paper>
      </Box>
    </Container>
  );
}
