import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  TextField,
  MenuItem,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
} from "@mui/material";
import {
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Upload as UploadIcon,
} from "@mui/icons-material";
import { lettersApi, type LetterListItem } from "../api/client";

const typeColors: Record<string, "error" | "warning" | "info" | "default"> = {
  hacker: "error",
  compromise: "warning",
  vulnerability: "info",
  other: "default",
};

const typeLabels: Record<string, string> = {
  hacker: "Хакерская группировка",
  compromise: "Компрометация",
  vulnerability: "Уязвимости",
  other: "Прочее",
};

export default function LetterList() {
  const navigate = useNavigate();
  const [letters, setLetters] = useState<LetterListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState("");
  const [search, setSearch] = useState("");
  const [deleteId, setDeleteId] = useState<number | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await lettersApi.list();
      setLetters(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const filtered = letters.filter((l) => {
    if (filterType && l.letter_type !== filterType) return false;
    if (search && !l.letter_number.includes(search)) return false;
    return true;
  });

  const handleDelete = async () => {
    if (deleteId === null) return;
    try {
      await lettersApi.delete(deleteId);
      setDeleteId(null);
      load();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Письма</Typography>
        <Button variant="contained" startIcon={<UploadIcon />} onClick={() => navigate("/upload")}>
          Загрузить письмо
        </Button>
      </Box>

      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <TextField
          size="small"
          label="Поиск по номеру"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ width: 250 }}
        />
        <TextField
          size="small"
          select
          label="Тип"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          sx={{ width: 200 }}
        >
          <MenuItem value="">Все</MenuItem>
          <MenuItem value="hacker">Хакерская группировка</MenuItem>
          <MenuItem value="compromise">Компрометация</MenuItem>
          <MenuItem value="vulnerability">Уязвимости</MenuItem>
          <MenuItem value="other">Прочее</MenuItem>
        </TextField>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>№</TableCell>
              <TableCell>Дата</TableCell>
              <TableCell>Тип</TableCell>
              <TableCell>Статус</TableCell>
              <TableCell align="center">Угроз</TableCell>
              <TableCell align="center">IOC</TableCell>
              <TableCell align="center">Уязв.</TableCell>
              <TableCell>Создано</TableCell>
              <TableCell align="center">Действия</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={9} align="center">
                  <Typography color="text.secondary" sx={{ py: 3 }}>
                    {letters.length === 0 ? "Нет писем. Загрузите первое письмо." : "Ничего не найдено"}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((letter) => (
                <TableRow key={letter.id} hover>
                  <TableCell>{letter.letter_number || "—"}</TableCell>
                  <TableCell>{letter.letter_date || "—"}</TableCell>
                  <TableCell>
                    <Chip
                      label={typeLabels[letter.letter_type] || letter.letter_type}
                      color={typeColors[letter.letter_type] || "default"}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={letter.status === "processed" ? "Обработан" : letter.status === "response_generated" ? "Ответ готов" : letter.status}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell align="center">{letter.threat_count}</TableCell>
                  <TableCell align="center">{letter.ioc_count}</TableCell>
                  <TableCell align="center">{letter.vuln_count}</TableCell>
                  <TableCell>{new Date(letter.created_at).toLocaleDateString("ru-RU")}</TableCell>
                  <TableCell align="center">
                    <IconButton size="small" onClick={() => navigate(`/letters/${letter.id}`)}>
                      <ViewIcon fontSize="small" />
                    </IconButton>
                    <IconButton size="small" onClick={() => setDeleteId(letter.id)}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={deleteId !== null} onClose={() => setDeleteId(null)}>
        <DialogTitle>Удалить письмо?</DialogTitle>
        <DialogContent>
          <Typography>Письмо и все связанные данные будут удалены безвозвратно.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteId(null)}>Отмена</Button>
          <Button color="error" onClick={handleDelete}>Удалить</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
