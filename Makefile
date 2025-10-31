HIVE_VERSION ?= 4.1.0
HADOOP_VERSION ?= 3.4.2

# Function to determine the correct module directory
get_hive_module_dir = \
  $(strip \
    $(if $(filter 3.%, $(1)), \
      hms-v3, \
      $(if $(filter 4.%, $(1)), \
        hms-v4, \
        $(error "Unsupported HIVE_VERSION=$(1). Expected a version starting with '3.' or '4.'.") \
      ) \
    ) \
  )

.PHONY: all
all:
	$(info Attempting to build for HIVE_VERSION=$(HIVE_VERSION))
	$(eval HIVE_MODULE_DIR := $(call get_hive_module_dir,$(HIVE_VERSION)))
	$(info Building $(HIVE_MODULE_DIR) with HIVE_VERSION=$(HIVE_VERSION) and HADOOP_VERSION=$(HADOOP_VERSION))
	mvn -f $(HIVE_MODULE_DIR)/pom.xml package -Dhive.version=$(HIVE_VERSION) -Dhadoop.version=$(HADOOP_VERSION)

.PHONY: clean
clean:
	mvn clean

.PHONY: test
test:
	$(eval HIVE_MODULE_DIR := $(call get_hive_module_dir,$(HIVE_VERSION)))
	mvn -f $(HIVE_MODULE_DIR)/pom.xml test -Dhive.version=$(HIVE_VERSION) -Dhadoop.version=$(HADOOP_VERSION)

.PHONY: integration-test
integration-test:
	$(eval HIVE_MODULE_DIR := $(call get_hive_module_dir,$(HIVE_VERSION)))
	mvn -f $(HIVE_MODULE_DIR)/pom.xml integration-test -Dhive.version=$(HIVE_VERSION) -Dhadoop.version=$(HADOOP_VERSION)

# Test all modules with default versions (from pom.xml)
.PHONY: test-all
test-all:
	mvn test

# Integration test all modules with default versions (from pom.xml)
.PHONY: integration-test-all
integration-test-all:
	mvn integration-test