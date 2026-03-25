#pragma once

#include <memory>

#include "IEventCollector.h"

std::unique_ptr<IEventCollector> CreateEventCollector();
