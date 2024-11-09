// handler/handler.go

package handler

import (
	"log/slog"
	"net/http"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
)

type Handler struct {
	usecase statistics.Usecase
	logger  *slog.Logger
}

func New(uc statistics.Usecase, logger *slog.Logger) *Handler {
	return &Handler{
		usecase: uc,
		logger:  logger,
	}
}

// TopLinks
// @Summary Статистика топ-5 популярных ссылок
// @Description Отображает топ-5 популярных ссылок с зонами "Red" и "Green" в виде анимированного графика
// @ID top-links
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-links [get]
func (h *Handler) TopLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	// Получаем статистику из usecase
	topLinks, err := h.usecase.GetTopLinks(ctx, 5)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Не удалось получить статистику топовых ссылок")
		logger.Error("Failed to retrieve top links statistics", slog.Any("error", err))
		return
	}

	// Создаем графики для зон "Red" и "Green"
	redChart, greenChart := createBarChart(topLinks)

	// Создаем страницу и добавляем на нее графики
	page := components.NewPage()
	page.PageTitle = "Top 5 Popular Links by Zone"
	page.Layout = components.PageFlexLayout // Устанавливаем горизонтальное расположение
	page.AddCharts(redChart, greenChart)

	// Рендерим страницу и отправляем клиенту
	w.Header().Set("Content-Type", "text/html")
	if err := page.Render(w); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Не удалось отобразить страницу с графиками")
		logger.Error("Failed to render page with charts", slog.Any("error", err))
		return
	}

	logger.Info("Successfully rendered top links statistics")
}

// createBarChart создает два отдельных бар-чарта для зон "Red" и "Green"
// и заполняет недостающие данные, чтобы всегда было 5 элементов
func createBarChart(topLinks map[string][]models.LinkStat) (*charts.Bar, *charts.Bar) {
	redData, greenData := topLinks["Red"], topLinks["Green"]

	// Убедимся, что в данных всегда есть 5 элементов
	redData = fillMissingData(redData, 5)
	greenData = fillMissingData(greenData, 5)

	// Создаем бар-чарт для зоны "Red"
	redBar := charts.NewBar()
	redBar.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:  "600px",
			Height: "600px",
			Theme:  types.ThemeChalk,
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top 5 Red Zone Links",
			Subtitle: "Based on Access Count",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show: opts.Bool(true),
		}),
	)

	var redRequests []string
	var redCounts []opts.BarData
	for _, stat := range redData {
		redRequests = append(redRequests, stat.Request)
		redCounts = append(redCounts, opts.BarData{Value: stat.AccessCount})
	}

	redBar.SetXAxis(redRequests).
		AddSeries("Access Count", redCounts).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Position:  "top",
				Formatter: "{c}",
			}),
			charts.WithItemStyleOpts(opts.ItemStyle{
				Color: "rgba(255, 99, 132, 0.6)", // Красный цвет
			}),
			charts.WithAnimationOpts(opts.Animation{
				AnimationEasing:   "elasticOut",
				AnimationDuration: 1000,
				AnimationDelay:    300,
			}),
		)

	// Создаем бар-чарт для зоны "Green"
	greenBar := charts.NewBar()
	greenBar.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:  "600px",
			Height: "600px",
			Theme:  types.ThemeChalk,
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top 5 Green Zone Links",
			Subtitle: "Based on Access Count",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show: opts.Bool(true),
		}),
	)

	var greenRequests []string
	var greenCounts []opts.BarData
	for _, stat := range greenData {
		greenRequests = append(greenRequests, stat.Request)
		greenCounts = append(greenCounts, opts.BarData{Value: stat.AccessCount})
	}

	greenBar.SetXAxis(greenRequests).
		AddSeries("Access Count", greenCounts).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Position:  "top",
				Formatter: "{c}",
			}),
			charts.WithItemStyleOpts(opts.ItemStyle{
				Color: "rgba(75, 192, 192, 0.6)", // Зеленый цвет
			}),
			charts.WithAnimationOpts(opts.Animation{
				AnimationEasing:   "elasticOut",
				AnimationDuration: 1000,
				AnimationDelay:    300,
			}),
		)

	return redBar, greenBar
}

// fillMissingData заполняет недостающие данные до нужной длины
func fillMissingData(data []models.LinkStat, length int) []models.LinkStat {
	for len(data) < length {
		data = append(data, models.LinkStat{
			Request:     "N/A",
			AccessCount: 0,
		})
	}
	return data
}
