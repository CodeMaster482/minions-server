package handler

import (
	"github.com/alexedwards/scs/v2"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/CodeMaster482/minions-server/common"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics"
	"github.com/CodeMaster482/minions-server/services/gateway/internal/statistics/models"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
	"log/slog"
)

type Handler struct {
	usecase        statistics.Usecase
	logger         *slog.Logger
	sessionManager *scs.SessionManager
}

func New(uc statistics.Usecase, logger *slog.Logger, sessionManager *scs.SessionManager) *Handler {
	return &Handler{
		usecase:        uc,
		logger:         logger,
		sessionManager: sessionManager,
	}
}

// TopRedLinksDay handles requests for the top 5 red links for today for user
// @Summary Top 5 red links for today
// @Description Displays a pie chart of the top 5 red (malicious) links accessed today
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-red-links-day [get]
func (h *Handler) TopRedLinksDay(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "day", "Red", "Топ 5 опасных ссылок за сегодня")
}

// TopGreenLinksDay handles requests for the top 5 green links for today for user
// @Summary Top 5 green links for today
// @Description Displays a pie chart of the top 5 green (safe) links accessed today
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-green-links-day [get]
func (h *Handler) TopGreenLinksDay(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "day", "Green", "Топ 5 безопасных ссылок за сегодня")
}

// TopRedLinksWeek handles requests for the top 5 red links for this week for user
// @Summary Top 5 red links for this week
// @Description Displays a pie chart of the top 5 red (malicious) links accessed this week
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-red-links-week [get]
func (h *Handler) TopRedLinksWeek(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "week", "Red", "Топ 5 опасных ссылок за неделю")
}

// TopGreenLinksWeek handles requests for the top 5 green links for this week for user
// @Summary Top 5 green links for this week
// @Description Displays a pie chart of the top 5 green (safe) links accessed this week
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-green-links-week [get]
func (h *Handler) TopGreenLinksWeek(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "week", "Green", "Топ 5 безопасных ссылок за неделю")
}

// TopRedLinksMonth handles requests for the top 5 red links for this month for user
// @Summary Top 5 red links for this month
// @Description Displays a pie chart of the top 5 red (malicious) links accessed this month
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-red-links-month [get]
func (h *Handler) TopRedLinksMonth(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "month", "Red", "Топ 5 опасных ссылок за месяц")
}

// TopGreenLinksMonth handles requests for the top 5 green links for this month for user
// @Summary Top 5 green links for this month
// @Description Displays a pie chart of the top 5 green (safe) links accessed this month
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 401 {object} common.ErrorResponse "Status Unauthorized"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-green-links-month [get]
func (h *Handler) TopGreenLinksMonth(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "month", "Green", "Топ 5 безопасных ссылок за месяц")
}

// topLinksByUserAndPeriod is a helper method that handles the logic for the above handlers
func (h *Handler) topLinksByUserAndPeriod(w http.ResponseWriter, r *http.Request, period string, zone string, title string) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	userID, ok := h.sessionManager.Get(ctx, "user_id").(int)
	if !ok {
		common.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		logger.Error("Failed to get user_id from session")
		return
	}

	topLinks, err := h.usecase.GetTopLinksByUserAndPeriod(ctx, &userID, period, zone, 5)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve top links statistics")
		logger.Error("Error retrieving top links", slog.Any("error", err))
		return
	}

	//Должно быть минимум 5 ссылок, заполняем пустоту
	topLinks = fillMissingData(topLinks, 5)

	pieChart := createPieChartWithColors(topLinks, title)

	page := components.NewPage()
	page.PageTitle = title
	page.AddCharts(pieChart)

	w.Header().Set("Content-Type", "text/html")
	if err := page.Render(w); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to render page with chart")
		logger.Error("Error rendering page", slog.Any("error", err))
		return
	}

	logger.Info("Successfully rendered top links", slog.String("title", title))
}

// TopRedLinksAllTime обрабатывает запросы на получение топ 5 красных (опасных) ссылок за все время.
// @Summary Top 5 Red Links All Time
// @Description Returns a pie chart of the top 5 red (malicious) links accessed all time.
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-red-links-all-time [get]
func (h *Handler) TopRedLinksAllTime(w http.ResponseWriter, r *http.Request) {
	h.topLinksByZone(w, r, "Red", "Топ 5 опасных ссылок за все время")
}

// TopGreenLinksAllTime обрабатывает запросы на получение топ 5 зеленых (безопасных) ссылок за все время.
// @Summary Top 5 Green Links All Time
// @Description Returns a pie chart of the top 5 green (safe) links accessed all time.
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/stat/top-green-links-all-time [get]
func (h *Handler) TopGreenLinksAllTime(w http.ResponseWriter, r *http.Request) {
	h.topLinksByZone(w, r, "Green", "Топ 5 безопасных ссылок за все время")
}

func (h *Handler) topLinksByZone(w http.ResponseWriter, r *http.Request, zone string, title string) {
	ctx := r.Context()
	logger := h.logger.With(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("remote_addr", r.RemoteAddr),
	)

	topLinks, err := h.usecase.GetTopLinksByZone(ctx, zone, 5)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve top links statistics")
		logger.Error("Error retrieving top links", slog.Any("error", err))
		return
	}

	// Должно быть минимум 5 ссылок, заполняем пустоту
	topLinks = fillMissingData(topLinks, 5)

	pieChart := createPieChartWithColors(topLinks, title)

	page := components.NewPage()
	page.PageTitle = title
	page.AddCharts(pieChart)

	w.Header().Set("Content-Type", "text/html")
	if err := page.Render(w); err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to render page with chart")
		logger.Error("Error rendering page", slog.Any("error", err))
		return
	}

	logger.Info("Successfully rendered top links", slog.String("title", title))
}

func createPieChartWithColors(data []models.LinkStat, _ string) *charts.Pie {
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:  "450px",
			Height: "360px",
			Theme:  types.ThemeChalk,
		}),
		//charts.WithTitleOpts(opts.Title{Title: title}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show: opts.Bool(true),
		}),
	)

	var pieItems []opts.PieData
	//colors := []string{"#FF5733", "#33FF57", "#3357FF", "#FF33A8", "#A833FF"}
	for _, stat := range data {
		pieItems = append(pieItems, opts.PieData{
			Name:  stat.Request,
			Value: stat.AccessCount,
			//ItemStyle: &opts.ItemStyle{
			//	Color: colors[i%len(colors)],
			//},
		})
	}

	for i, item := range pieItems {
		name := item.Name

		name = strings.TrimPrefix(name, "http://")

		name = strings.TrimPrefix(name, "https://")

		if utf8.RuneCountInString(name) > 25 {
			runes := []rune(name)
			name = string(runes[:25])
			name += "..."
		}
		pieItems[i].Name = name
	}

	pie.AddSeries("Links", pieItems).
		SetSeriesOptions(
			charts.WithLabelOpts(
				opts.Label{
					Show:      opts.Bool(true),
					Formatter: "{b}: {c}",
				},
			),
		)

	return pie
}

func truncateString(str string, num int) string {
	if utf8.RuneCountInString(str) > num {
		runes := []rune(str)
		return string(runes[:num])
	}
	return str
}

func createPieChart(data []models.LinkStat, title string) *charts.Pie {
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:  "600px",
			Height: "600px",
			Theme:  types.ThemeChalk,
		}),
		charts.WithTitleOpts(opts.Title{Title: title}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show: opts.Bool(true),
		}),
	)

	var pieItems []opts.PieData
	for _, stat := range data {
		pieItems = append(pieItems, opts.PieData{
			Name:  stat.Request,
			Value: stat.AccessCount,
		})
	}

	pie.AddSeries("Links", pieItems).
		SetSeriesOptions(
			charts.WithLabelOpts(
				opts.Label{
					Show:      opts.Bool(true),
					Formatter: "{b}: {c}",
				},
			),
		)

	return pie
}

func fillMissingData(data []models.LinkStat, length int) []models.LinkStat {
	for len(data) < length {
		data = append(data, models.LinkStat{
			Request:     "N/A",
			AccessCount: 0,
		})
	}
	return data
}
