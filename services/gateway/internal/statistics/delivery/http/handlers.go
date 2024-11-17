package handler

import (
	"github.com/alexedwards/scs/v2"
	"net/http"

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

// TopRedLinksDay handles requests for the top 5 red links for today
// @Summary Top 5 red links for today
// @Description Displays a pie chart of the top 5 red (malicious) links accessed today
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-red-links-day [get]
func (h *Handler) TopRedLinksDay(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "day", "Red", "Топ 5 опасных ссылок за сегодня")
}

// TopGreenLinksDay handles requests for the top 5 green links for today
// @Summary Top 5 green links for today
// @Description Displays a pie chart of the top 5 green (safe) links accessed today
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-green-links-day [get]
func (h *Handler) TopGreenLinksDay(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "day", "Green", "Топ 5 безопасных ссылок за сегодня")
}

// TopRedLinksWeek handles requests for the top 5 red links for this week
// @Summary Top 5 red links for this week
// @Description Displays a pie chart of the top 5 red (malicious) links accessed this week
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-red-links-week [get]
func (h *Handler) TopRedLinksWeek(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "week", "Red", "Топ 5 опасных ссылок за неделю")
}

// TopGreenLinksWeek handles requests for the top 5 green links for this week
// @Summary Top 5 green links for this week
// @Description Displays a pie chart of the top 5 green (safe) links accessed this week
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-green-links-week [get]
func (h *Handler) TopGreenLinksWeek(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "week", "Green", "Топ 5 безопасных ссылок за неделю")
}

// TopRedLinksMonth handles requests for the top 5 red links for this month
// @Summary Top 5 red links for this month
// @Description Displays a pie chart of the top 5 red (malicious) links accessed this month
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-red-links-month [get]
func (h *Handler) TopRedLinksMonth(w http.ResponseWriter, r *http.Request) {
	h.topLinksByUserAndPeriod(w, r, "month", "Red", "Топ 5 опасных ссылок за месяц")
}

// TopGreenLinksMonth handles requests for the top 5 green links for this month
// @Summary Top 5 green links for this month
// @Description Displays a pie chart of the top 5 green (safe) links accessed this month
// @Tags Statistics
// @Produce html
// @Success 200 {string} string "HTML with embedded chart"
// @Failure 500 {object} common.ErrorResponse "Internal Server Error"
// @Router /api/statistics/top-green-links-month [get]
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

	// Get userID from session if the user is authenticated
	userID, ok := h.sessionManager.Get(ctx, "user_id").(int)
	if !ok {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to get user_id from cookie")
		logger.Error("Failed to get user_id from cookie")
		return
	}

	// Get top links from usecase
	topLinks, err := h.usecase.GetTopLinksByUserAndPeriod(ctx, &userID, period, zone, 5)
	if err != nil {
		common.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve top links statistics")
		logger.Error("Error retrieving top links", slog.Any("error", err))
		return
	}

	// Ensure we always have 5 data points
	topLinks = fillMissingData(topLinks, 5)

	// Create pie chart
	pieChart := createPieChart(topLinks, title)

	// Create page and render
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

// createPieChart creates a pie chart for the given data
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

// fillMissingData fills missing data to ensure there are always 'length' items
func fillMissingData(data []models.LinkStat, length int) []models.LinkStat {
	for len(data) < length {
		data = append(data, models.LinkStat{
			Request:     "N/A",
			AccessCount: 0,
		})
	}
	return data
}
