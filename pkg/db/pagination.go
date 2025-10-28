package db

import "fmt"

// PageRequest represents pagination parameters
type PageRequest struct {
	Page     int
	PageSize int
}

// PageResponse represents paginated response metadata
type PageResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
}

// NewPageRequest creates a new pagination request with defaults
func NewPageRequest(page, pageSize int) PageRequest {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20 // default page size
	}
	return PageRequest{
		Page:     page,
		PageSize: pageSize,
	}
}

// Offset returns the SQL OFFSET value
func (p PageRequest) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Limit returns the SQL LIMIT value
func (p PageRequest) Limit() int {
	return p.PageSize
}

// SQLLimitOffset returns the LIMIT and OFFSET clause for SQL queries
func (p PageRequest) SQLLimitOffset() string {
	return fmt.Sprintf("LIMIT %d OFFSET %d", p.Limit(), p.Offset())
}

// NewPageResponse creates a paginated response
func NewPageResponse(page, pageSize int, totalItems int64) PageResponse {
	totalPages := int(totalItems) / pageSize
	if int(totalItems)%pageSize > 0 {
		totalPages++
	}

	return PageResponse{
		Page:       page,
		PageSize:   pageSize,
		TotalItems: totalItems,
		TotalPages: totalPages,
	}
}

