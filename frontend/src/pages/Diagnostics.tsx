import { useCallback, useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
} from "@mui/material";
import {
  Memory as MemoryIcon,
  Speed as SpeedIcon,
  Storage as StorageIcon,
  DeveloperBoard as CpuIcon,
  MonitorHeart as MonitorHeartIcon,
} from "@mui/icons-material";
import { diagnosticsApi, type DiagnosticsResponse, type ServiceHealth } from "../api/client";

const POLL_MS = 4000;

function fmtTime(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("ru-RU");
}

function fmtUptime(sec: number): string {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `${h} ч ${m} мин`;
}

export default function Diagnostics() {
  const [data, setData] = useState<DiagnosticsResponse | null>(null);
  const [bus, setBus] = useState<{ total: number; topics: Array<{ topic: string; count: number; last_id: number }> } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [d, b] = await Promise.all([diagnosticsApi.get(), diagnosticsApi.bus()]);
      setData(d.data);
      setBus(b.data);
      setError("");
    } catch (err: any) {
      setError(err.response?.data?.detail || (err as Error)?.message || "Ошибка диагностики");
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const serviceCheck = (s: ServiceHealth): string => {
    if (data?.gateway && s.name === "gateway") {
      const g = data.gateway;
      return g.reachable ? `OK, ${g.latency_ms} мс` : `недоступен: ${g.error || "нет ответа"}`;
    }
    const ok = s.pid_exists && (s.heartbeat_age_sec ?? Number.POSITIVE_INFINITY) <= 60;
    return ok ? `OK, сердцебиение ${s.heartbeat_age_sec} с` : `нет процесса (pid ${s.pid ?? "—"})`;
  };

  const allAlive = data ? data.services.filter((s) => s.alive).length : 0;

  const resourceCards = data ? [
    { label: "CPU системы", value: `${data.system.cpu_percent}%`, icon: <CpuIcon />, color: "#1976d2" },
    { label: "RAM занято", value: `${Math.round((data.system.memory_mb / data.system.memory_total_mb) * 100)}% (${data.system.memory_mb} МБ)`, icon: <MemoryIcon />, color: "#7b1fa2" },
    { label: "Диск свободно", value: `${data.system.disk_free_gb} ГБ`, icon: <StorageIcon />, color: "#388e3c" },
    { label: "LLM GPU-процесс", value: data.llm.reachable ? "доступен" : "не запущен", icon: <SpeedIcon />, color: data.llm.reachable ? "#388e3c" : "#d32f2f" },
  ] : [];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Диагностика</Typography>
        <Typography variant="caption" color="text.secondary">
          Автообновление каждые {POLL_MS / 1000} с
        </Typography>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {loading && !data && <Typography color="text.secondary">Загрузка...</Typography>}

      {data && (
        <>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
            <MonitorHeartIcon color={allAlive === data.services.length ? "success" : "warning"} />
            <Typography variant="body2" color="text.secondary">
              Модулей запущено: {allAlive} из {data.services.length}
            </Typography>
          </Box>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {resourceCards.map((card) => (
              <Grid size={{ xs: 12, sm: 6, md: 3 }} key={card.label}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <Box>
                        <Typography color="text.secondary" variant="body2">{card.label}</Typography>
                        <Typography variant="h6" sx={{ mt: 1 }}>{card.value}</Typography>
                      </Box>
                      <Box sx={{ color: card.color, "& svg": { fontSize: 36 } }}>{card.icon}</Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 7 }}>
              <Typography variant="h6" gutterBottom>Модули</Typography>
              <TableContainer component={Paper} sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Модуль</TableCell>
                      <TableCell>PID</TableCell>
                      <TableCell>Статус</TableCell>
                      <TableCell>Запущен</TableCell>
                      <TableCell>Активность</TableCell>
                      <TableCell>Проверка</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.services.map((s) => (
                      <TableRow key={s.name}>
                        <TableCell>{s.name}</TableCell>
                        <TableCell>{s.pid ?? "—"}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={s.alive ? "Работает" : "Не работает"}
                            color={s.alive ? "success" : "error"}
                            variant={s.alive ? "filled" : "outlined"}
                          />
                        </TableCell>
                        <TableCell>{fmtTime(s.started)}</TableCell>
                        <TableCell>
                          {fmtTime(s.last_seen)}
                          {s.heartbeat_age_sec != null && (
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                              {s.heartbeat_age_sec} с назад
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={serviceCheck(s).startsWith("OK") ? "OK" : "Стоп"}
                            color={serviceCheck(s).startsWith("OK") ? "success" : "error"}
                            variant="outlined"
                          />
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                            {serviceCheck(s)}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Typography variant="h6" gutterBottom>Очередь сообщений</Typography>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Топик</TableCell>
                      <TableCell>Сообщений</TableCell>
                      <TableCell>Последний ID</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {bus?.topics.length ? (
                      bus.topics.map((t) => (
                        <TableRow key={t.topic}>
                          <TableCell>{t.topic}</TableCell>
                          <TableCell>{t.count}</TableCell>
                          <TableCell>{t.last_id}</TableCell>
                        </TableRow>
                      ))
                    ) : (
                      <TableRow><TableCell colSpan={3} align="center">Нет сообщений</TableCell></TableRow>
                    )}
                    <TableRow>
                      <TableCell colSpan={2}><b>Всего</b></TableCell>
                      <TableCell><b>{bus?.total ?? 0}</b></TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>

            <Grid size={{ xs: 12, md: 5 }}>
              <Typography variant="h6" gutterBottom>База данных</Typography>
              <Paper variant="outlined" sx={{ p: 1.5, mb: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip
                    size="small"
                    label={data.db.reachable ? "Работает" : "Недоступна"}
                    color={data.db.reachable ? "success" : "error"}
                    variant={data.db.reachable ? "filled" : "outlined"}
                  />
                  <Typography variant="body2" color="text.secondary">
                    {data.db.reachable ? `отклик ${data.db.latency_ms} мс` : data.db.error || "нет ответа"}
                  </Typography>
                </Box>
              </Paper>

              <Typography variant="h6" gutterBottom>Внешние подключения</Typography>
              <TableContainer component={Paper} sx={{ mb: 1 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Сервис</TableCell>
                      <TableCell>Статус</TableCell>
                      <TableCell>Время</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {data.external.map((p) => (
                      <TableRow key={p.name}>
                        <TableCell>{p.name}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={p.reachable ? "Доступен" : "Недоступен"}
                            color={p.reachable ? "success" : "error"}
                            variant={p.reachable ? "filled" : "outlined"}
                          />
                          {p.http_status != null && (
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                              HTTP {p.http_status}
                            </Typography>
                          )}
                          {!p.reachable && p.error && (
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                              {p.error}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>{p.reachable ? `${p.latency_ms} мс` : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 3 }}>
                Проверки выполняются сервером (gateway), а не браузером — доступ к ФСТЭК/BDU есть только
                у сервера. «Доступен» = получен любой HTTP-ответ (в т.ч. 404). «Недоступен» — это
                DNS/таймаут/TLS: например, bdu.fstec.ru может требовать доверенный CA-бандл на сервере.
              </Typography>

              <Typography variant="h6" gutterBottom>Нейронная сеть (LLM)</Typography>
              <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                <Box sx={{ display: "flex", gap: 1, alignItems: "center", mb: 1 }}>
                  <Chip
                    size="small"
                    label={data.llm.reachable ? "Модель доступна" : "Модель не запущена"}
                    color={data.llm.reachable ? "success" : "error"}
                  />
                  <Chip size="small" label={`Провайдер: ${data.llm.provider}`} variant="outlined" />
                </Box>
                <Typography variant="body2">Модель: <b>{data.llm.model}</b></Typography>
                <Typography variant="body2" color="text.secondary">URL: {data.llm.base_url}</Typography>
                {data.llm.latency_ms > 0 && (
                  <Typography variant="body2" color="text.secondary">Отклик: {data.llm.latency_ms} мс</Typography>
                )}
                {data.llm.error && <Typography variant="body2" color="text.secondary">{data.llm.error}</Typography>}
                {data.llm.note && <Alert severity="info" sx={{ mt: 1 }}>{data.llm.note}</Alert>}
              </Paper>

              <Typography variant="h6" gutterBottom>Gateway</Typography>
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Typography variant="body2">CPU процесса: {data.system.gateway_proc_cpu_percent}%</Typography>
                <Typography variant="body2">RAM процесса: {data.system.gateway_proc_memory_mb} МБ</Typography>
                <Typography variant="body2">Аптайм: {fmtUptime(data.system.gateway_uptime_sec)}</Typography>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
    </Box>
  );
}