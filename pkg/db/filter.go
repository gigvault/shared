package db

import (
	"fmt"
	"strings"
)

// FilterOperator represents SQL comparison operators
type FilterOperator string

const (
	OpEqual          FilterOperator = "="
	OpNotEqual       FilterOperator = "!="
	OpGreaterThan    FilterOperator = ">"
	OpGreaterOrEqual FilterOperator = ">="
	OpLessThan       FilterOperator = "<"
	OpLessOrEqual    FilterOperator = "<="
	OpLike           FilterOperator = "LIKE"
	OpILike          FilterOperator = "ILIKE"
	OpIn             FilterOperator = "IN"
	OpNotIn          FilterOperator = "NOT IN"
	OpIsNull         FilterOperator = "IS NULL"
	OpIsNotNull      FilterOperator = "IS NOT NULL"
)

// Filter represents a SQL filter condition
type Filter struct {
	Field    string
	Operator FilterOperator
	Value    interface{}
}

// FilterBuilder helps build SQL WHERE clauses
type FilterBuilder struct {
	filters []Filter
	args    []interface{}
}

// NewFilterBuilder creates a new filter builder
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{
		filters: make([]Filter, 0),
		args:    make([]interface{}, 0),
	}
}

// Add adds a filter condition
func (fb *FilterBuilder) Add(field string, operator FilterOperator, value interface{}) *FilterBuilder {
	fb.filters = append(fb.filters, Filter{
		Field:    field,
		Operator: operator,
		Value:    value,
	})
	return fb
}

// Build constructs the WHERE clause and returns it with args
func (fb *FilterBuilder) Build() (string, []interface{}) {
	if len(fb.filters) == 0 {
		return "", nil
	}

	conditions := make([]string, 0, len(fb.filters))
	argIndex := 1

	for _, filter := range fb.filters {
		switch filter.Operator {
		case OpIsNull, OpIsNotNull:
			conditions = append(conditions, fmt.Sprintf("%s %s", filter.Field, filter.Operator))
		case OpIn, OpNotIn:
			// For IN/NOT IN, assume value is a slice
			conditions = append(conditions, fmt.Sprintf("%s %s ($%d)", filter.Field, filter.Operator, argIndex))
			fb.args = append(fb.args, filter.Value)
			argIndex++
		default:
			conditions = append(conditions, fmt.Sprintf("%s %s $%d", filter.Field, filter.Operator, argIndex))
			fb.args = append(fb.args, filter.Value)
			argIndex++
		}
	}

	whereClause := "WHERE " + strings.Join(conditions, " AND ")
	return whereClause, fb.args
}

// BuildWithPrefix is like Build but adds a custom prefix (e.g., "AND" instead of "WHERE")
func (fb *FilterBuilder) BuildWithPrefix(prefix string) (string, []interface{}) {
	clause, args := fb.Build()
	if clause == "" {
		return "", args
	}
	return strings.Replace(clause, "WHERE", prefix, 1), args
}
