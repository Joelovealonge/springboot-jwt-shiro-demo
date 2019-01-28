package com.alonge.shirodemo.mapper;

import com.alonge.shirodemo.domain.UrlFilter;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UrlFilterMapper {

    List<UrlFilter> getUrlFilters();
}
