package api

import (
	"net/http"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

type integrationOrderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

type orderItemResponse struct {
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	PriceCents  int64  `json:"price_cents"`
}

type productResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ImagePath   string `json:"image_path"`
	PriceCents  int64  `json:"price_cents"`
}

type orderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

type Handler struct {
	accountStore      *accounts.Store
	orderStore        *orders.Store
	productStore      *storefront.Store
	apiStore          *Store
	logger            *logging.Logger
	maxProductResults int64
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, productStore *storefront.Store, apiStore *Store, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, productStore: productStore, apiStore: apiStore,
		logger: logger, maxProductResults: int64(maxProductResults),
	}
}

func (handler *Handler) AccountOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	orderResponses := make([]orderResponse, 0, len(orders))

	for _, order := range orders {
		orderResponses = append(orderResponses, orderResponse{
			ID:         order.ID,
			Status:     order.Status,
			TotalCents: order.TotalCents,
			CreatedAt:  order.CreatedAt,
		})
	}

	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"orders": orderResponses,
	})
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}

	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}

	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	// Check whether the order exists and belongs to the authenticated user.
	if !found || order.UserID != current.User.ID {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}

	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	itemResponses := make([]orderItemResponse, 0, len(items))
	for _, item := range items {
		itemResponses = append(itemResponses, orderItemResponse{
			ProductID:   item.ProductID,
			ProductName: item.ProductName,
			Quantity:    item.Quantity,
			PriceCents:  item.PriceCents,
		})
	}

	publicOrder := orderResponse{
		ID:         order.ID,
		Status:     order.Status,
		TotalCents: order.TotalCents,
		CreatedAt:  order.CreatedAt,
	}

	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"order": publicOrder,
		"items": itemResponses,
	})
}

func (handler *Handler) Products(responseWriter http.ResponseWriter, request *http.Request) {
	products, err := handler.productStore.ListProducts(
		request.Context(),
		handler.maxProductResults,
	)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	productResponses := make([]productResponse, 0, len(products))

	for _, product := range products {
		productResponses = append(productResponses, productResponse{
			ID:          product.ID,
			Name:        product.Name,
			Description: product.Description,
			ImagePath:   product.ImagePath,
			PriceCents:  product.PriceCents,
		})
	}

	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"products": productResponses,
	})
}

func (handler *Handler) WarehouseOrders(responseWriter http.ResponseWriter, request *http.Request) {
	// Step 1: Get API key from request header
	apiKey := request.Header.Get("X-API-Key")

	// Step 2: Check if API key is missing
	if apiKey == "" {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{
			"error": "API key required",
		})
		return
	}

	// Step 3: Find and validate API key
	key, found, err := handler.apiStore.FindKey(request.Context(), apiKey)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{
			"error": "Invalid API key",
		})
		return
	}

	// Step 4: Check required scope
	if key.Scope != "orders:read" {
		httpx.RespondWithJSON(responseWriter, http.StatusForbidden, map[string]string{
			"error": "Insufficient permissions",
		})
		return
	}

	// Step 5: Consume daily quota
	quota, err := handler.apiStore.ConsumeQuota(request.Context(), key.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	// Step 6: Set quota headers
	SetQuotaHeaders(responseWriter, quota)

	// Step 7: Check if quota is exhausted
	if !quota.Allowed {
		RespondWithQuotaExhausted(responseWriter, quota)
		return
	}

	// Step 8: Get all orders
	orders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	responses := make([]integrationOrderResponse, 0, len(orders))

	for _, order := range orders {
		responses = append(responses, integrationOrderResponse{
			ID:         order.ID,
			Status:     order.Status,
			TotalCents: order.TotalCents,
			CreatedAt:  order.CreatedAt,
		})
	}

	// Step 9: Return successful response with quota information
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"integration": "Warehouse Fulfillment Integration",
		"orders":      responses,
		"quota":       ToQuotaResponse(quota),
	})
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	httpx.RespondWithError(responseWriter, http.StatusInternalServerError, err.Error())
}
