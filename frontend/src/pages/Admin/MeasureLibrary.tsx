import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControlLabel,
  IconButton,
  InputAdornment,
  MenuItem,
  Paper,
  Snackbar,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Search as SearchIcon,
} from "@mui/icons-material";
import {
  measureLibraryApi,
  type MeasureLibraryInput,
  type MeasureLibraryItem,
} from "../../api/client";

const TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "Без типа" },
  { value: "phishing", label: "Фишинг" },
  { value: "malware_attack", label: "Вредоносная атака" },
  { value: "compromise", label: "Компрометация" },
  { value: "clickfix", label: "ClickFix" },
  { value: "vulnerability", label: "Уязвимость" },
  { value: "hacker", label: "Хакерская атака" },
];

const EMPTY_FORM: MeasureLibraryInput = {
  text: "",
  threat_type: "",
  tags: "",
  addr_inflection: false,
};

function typeLabel(value: string) {
  return TYPE_OPTIONS.find((option) => option.value === value)?.label || value || "Без типа";
}

function splitTags(value: string) {
  return value.split(",").map((tag) => tag.trim()).filter(Boolean);
}

export default function MeasureLibrary() {
  const [items, setItems] = useState<MeasureLibraryItem[]>([]);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [snack, setSnack] = useState("");
  const [dialog, setDialog] = useState<"create" | "edit" | "delete" | null>(null);
  const [editing, setEditing] = useState<MeasureLibraryItem | null>(null);
  const [form, setForm] = useState<MeasureLibraryInput>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await measureLibraryApi.list();
      setItems(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err?.message || "Не удалось загрузить базу мер");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      if (typeFilter !== "all" && item.threat_type !== typeFilter) return false;
      if (!needle) return true;
      return [item.text, item.tags, item.source, typeLabel(item.threat_type)]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [items, query, typeFilter]);

  const counts = useMemo(() => {
    const byType = new Map<string, number>();
    for (const item of items) {
      byType.set(item.threat_type, (byType.get(item.threat_type) || 0) + 1);
    }
    return byType;
  }, [items]);

  const openCreate = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setError("");
    setDialog("create");
  };

  const openEdit = (item: MeasureLibraryItem) => {
    setEditing(item);
    setForm({
      text: item.text,
      threat_type: item.threat_type,
      tags: item.tags,
      addr_inflection: item.addr_inflection,
    });
    setError("");
    setDialog("edit");
  };

  const openDelete = (item: MeasureLibraryItem) => {
    setEditing(item);
    setError("");
    setDialog("delete");
  };

  const save = async () => {
    const text = form.text.trim();
    if (!text) {
      setError("Текст меры обязателен");
      return;
    }
    setSaving(true);
    setError("");
    try {
      if (dialog === "create") {
        const { data } = await measureLibraryApi.create({ ...form, text });
        setSnack(data.status === "exists" ? "Такая мера уже есть в базе" : "Мера добавлена");
      } else if (dialog === "edit" && editing) {
        await measureLibraryApi.update(editing.id, { ...form, text });
        setSnack("Мера обновлена");
      }
      setDialog(null);
      await load();
    } catch (err: any) {
      setError(err.response?.data?.detail || err?.message || "Не удалось сохранить меру");
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!editing) return;
    setSaving(true);
    setError("");
    try {
      await measureLibraryApi.remove(editing.id);
      setSnack("Мера удалена");
      setDialog(null);
      await load();
    } catch (err: any) {
      setError(err.response?.data?.detail || err?.message || "Не удалось удалить меру");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 2, mb: 1 }}>
        <Box>
          <Typography variant="h5">База мер</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Все одобренные меры, из которых формируются письма. Всего: {items.length}.
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<AddIcon />} onClick={openCreate}>
          Добавить меру
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

      <Paper sx={{ p: 1.5, mb: 2, display: "flex", gap: 1.5, flexWrap: "wrap", alignItems: "center" }}>
        <TextField
          size="small"
          placeholder="Поиск по тексту, тегам или источнику"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          sx={{ minWidth: 320, flex: 1 }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            },
          }}
        />
        <TextField
          select
          size="small"
          label="Тип угрозы"
          value={typeFilter}
          onChange={(event) => setTypeFilter(event.target.value)}
          sx={{ minWidth: 210 }}
        >
          <MenuItem value="all">Все типы ({items.length})</MenuItem>
          {TYPE_OPTIONS.map((option) => (
            <MenuItem key={option.value || "empty"} value={option.value}>
              {option.label} ({counts.get(option.value) || 0})
            </MenuItem>
          ))}
        </TextField>
        <Chip label={`Показано: ${filtered.length}`} variant="outlined" />
      </Paper>

      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell width={64}>ID</TableCell>
              <TableCell>Текст меры</TableCell>
              <TableCell width={170}>Тип угрозы</TableCell>
              <TableCell width={220}>Теги</TableCell>
              <TableCell width={90}>Склонение</TableCell>
              <TableCell width={100}>Источник</TableCell>
              <TableCell align="center" width={100}>Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} align="center">Загрузка...</TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center">Меры не найдены</TableCell>
              </TableRow>
            ) : (
              filtered.map((item) => (
                <TableRow key={item.id} hover>
                  <TableCell>{item.id}</TableCell>
                  <TableCell sx={{ whiteSpace: "pre-wrap", maxWidth: 720 }}>{item.text}</TableCell>
                  <TableCell>
                    <Chip size="small" label={typeLabel(item.threat_type)} variant="outlined" />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                      {splitTags(item.tags).length
                        ? splitTags(item.tags).map((tag) => <Chip key={tag} size="small" label={tag} />)
                        : <Typography variant="body2" color="text.secondary">—</Typography>}
                    </Box>
                  </TableCell>
                  <TableCell>{item.addr_inflection ? "Да" : "Нет"}</TableCell>
                  <TableCell><Typography variant="body2" color="text.secondary">{item.source}</Typography></TableCell>
                  <TableCell align="center">
                    <Tooltip title="Редактировать">
                      <IconButton size="small" onClick={() => openEdit(item)} aria-label="Редактировать меру">
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Удалить">
                      <IconButton size="small" color="error" onClick={() => openDelete(item)} aria-label="Удалить меру">
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={dialog === "create" || dialog === "edit"} onClose={() => setDialog(null)} fullWidth maxWidth="md">
        <DialogTitle>{dialog === "create" ? "Новая мера" : `Мера №${editing?.id ?? ""}`}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            multiline
            minRows={4}
            margin="dense"
            label="Текст меры"
            value={form.text}
            onChange={(event) => setForm((current) => ({ ...current, text: event.target.value }))}
          />
          <TextField
            select
            fullWidth
            margin="dense"
            label="Тип угрозы"
            value={form.threat_type}
            onChange={(event) => setForm((current) => ({ ...current, threat_type: event.target.value }))}
          >
            {TYPE_OPTIONS.map((option) => (
              <MenuItem key={option.value || "empty"} value={option.value}>{option.label}</MenuItem>
            ))}
          </TextField>
          <TextField
            fullWidth
            margin="dense"
            label="Теги (через запятую)"
            value={form.tags}
            onChange={(event) => setForm((current) => ({ ...current, tags: event.target.value }))}
          />
          <FormControlLabel
            control={(
              <Switch
                checked={form.addr_inflection}
                onChange={(event) => setForm((current) => ({ ...current, addr_inflection: event.target.checked }))}
              />
            )}
            label="Нужно склонение по адресам"
            sx={{ mt: 1 }}
          />
          {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)} disabled={saving}>Отмена</Button>
          <Button variant="contained" onClick={save} disabled={saving}>
            {saving ? "Сохранение..." : "Сохранить"}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={dialog === "delete"} onClose={() => setDialog(null)}>
        <DialogTitle>Удалить меру?</DialogTitle>
        <DialogContent>
          <DialogContentText>Мера №{editing?.id} будет удалена из базы.</DialogContentText>
          <DialogContentText sx={{ mt: 1, whiteSpace: "pre-wrap" }}>{editing?.text}</DialogContentText>
          {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialog(null)} disabled={saving}>Отмена</Button>
          <Button color="error" variant="contained" onClick={remove} disabled={saving}>
            {saving ? "Удаление..." : "Удалить"}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={4000}
        onClose={() => setSnack("")}
        message={snack}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      />
    </Box>
  );
}
