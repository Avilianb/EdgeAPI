package dnsla

import (
	"errors"

	"github.com/iwind/TeaGo/types"
)

type BaseResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (this *BaseResponse) Success() bool {
	return this.Code == 200
}

func (this *BaseResponse) Error() error {
	return errors.New("code: " + types.String(this.Code) + ", message: " + this.Message)
}

type DomainListResponse struct {
	BaseResponse
	Data struct {
		Results []struct {
			Id     string `json:"id"`
			Domain string `json:"domain"`
		} `json:"results"`
	} `json:"data"`
}

type DomainResponse struct {
	BaseResponse
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

type RecordListResponse struct {
	BaseResponse
	Data struct {
		Results []struct {
			Id       string `json:"id"`
			Host     string `json:"host"`
			Type     int    `json:"type"`
			Data     string `json:"data"`
			LineCode string `json:"lineCode"`
			TTL      int    `json:"ttl"`
		} `json:"results"`
	} `json:"data"`
}

type AllLineListResponse struct {
	BaseResponse
	Data []AllLineListResponseChild `json:"data"`
}

type AllLineListResponseChild struct {
	Id       string                     `json:"id"`
	Code     string                     `json:"code"`
	Name     string                     `json:"name"`
	Children []AllLineListResponseChild `json:"children"`
}

type RecordCreateResponse struct {
	BaseResponse
	Data struct {
		Id any `json:"id"`
	} `json:"data"`
}

type RecordUpdateResponse struct {
	BaseResponse
}

type RecordDeleteResponse struct {
	BaseResponse
}
